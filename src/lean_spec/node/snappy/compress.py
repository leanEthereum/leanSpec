"""
Snappy compression implementation.

This module implements the compression (encoding) side of the Snappy codec.


WHAT IS SNAPPY?
---------------
Snappy is an LZ77-variant compression algorithm developed by Google.
It prioritizes speed over compression ratio.


HOW COMPRESSION WORKS
---------------------
The algorithm scans input data looking for repeated byte sequences.

When it finds a repeat, instead of storing the bytes again, it stores:
  "Go back X bytes and copy Y bytes from there."

This is called a "copy" or "backreference".

Bytes that don't repeat are stored as-is. These are called "literals".


Example:
-------
Input:  "ABCDABCD" (8 bytes)

The compressor sees:
  - Position 0-3: "ABCD" (no match yet, emit as literal)
  - Position 4-7: "ABCD" (matches position 0!)

Output:
  - Literal: "ABCD" (4 bytes)
  - Copy: go back 4, copy 4

Result: 4 literal bytes + 1 copy tag ≈ 6 bytes (saved 2 bytes).


THE HASH TABLE
--------------
To find matches quickly, we use a hash table.

For each position, we:
  1. Hash the next 4 bytes.
  2. Look up the hash in the table.
  3. If found, check if the bytes actually match (hash collisions exist).
  4. Store our current position in the table for future lookups.

This gives O(1) match lookup per position.


BLOCK PROCESSING
----------------
Large inputs are split into 64KB blocks.
Each block is compressed independently.

This bounds memory usage and enables streaming.


Reference: https://github.com/google/snappy
"""

from __future__ import annotations

from .constants import (
    BLOCK_SIZE,
    HASH_MULTIPLIER,
    INPUT_MARGIN_BYTES,
    MAX_HASH_TABLE_BITS,
    MIN_HASH_TABLE_BITS,
)
from .encoding import encode_copy_tag, encode_literal_tag, encode_varint32


def compress(data: bytes) -> bytes:
    """Compress data using the Snappy algorithm.

    Args:
        data: Uncompressed input bytes.

    Returns:
        Snappy-compressed bytes.

    Output format:
        [varint: uncompressed length] [tag1] [tag2] [tag3] ...

    The length prefix allows the decompressor to pre-allocate memory.
    """
    # Handle empty input.
    #
    # Even empty data needs a length prefix (varint 0).
    if not data:
        return encode_varint32(0)

    # Build output buffer.
    #
    # Start with the uncompressed length as a varint.
    # The decompressor reads this first to allocate the output buffer.
    output = bytearray(encode_varint32(len(data)))

    # Process input in blocks.
    #
    # Why blocks?
    #   - Bounds memory usage (hash table size is proportional to block size).
    #   - Enables streaming (can compress/decompress without full input).
    #   - 64KB is a good balance between compression ratio and memory.
    offset = 0
    while offset < len(data):
        # Extract this block (up to 64KB).
        block_end = min(offset + BLOCK_SIZE, len(data))
        block = data[offset:block_end]

        # Compress and append.
        compressed_block = _compress_block(block)
        output.extend(compressed_block)

        # Move to next block.
        offset = block_end

    return bytes(output)


def max_compressed_length(source_bytes: int) -> int:
    """Calculate the maximum possible compressed length for a given input size.

    Snappy guarantees that compressed output never exceeds this size.
    Useful for pre-allocating buffers.

    Args:
        source_bytes: Uncompressed data size.

    Returns:
        Maximum possible compressed size.

    The worst case is incompressible data (random bytes).
    Every 64 bytes needs a 5-byte literal tag, giving ~8% overhead.
    """
    # Components:
    #   - 5 bytes: maximum varint size for 32-bit length
    #   - source_bytes: the data itself
    #   - source_bytes // 6: overhead for literal tags (worst case)
    #   - 1: rounding
    return 5 + source_bytes + source_bytes // 6 + 1


def _compress_block(block: bytes) -> bytes:
    """Compress a single block (up to 64KB).

    This is the heart of the compression algorithm.

    Args:
        block: Input block (max 64KB).

    Returns:
        Compressed bytes for this block.
    """
    # Handle small blocks.
    #
    # We need at least 4 bytes to compute a hash.
    # Smaller blocks are emitted as literals.
    if len(block) < 4:
        return _emit_literal(block)

    # Initialize hash table.
    #
    # The hash table maps: hash(4 bytes) -> position in block.
    #
    # When we see 4 bytes, we:
    #   1. Compute their hash.
    #   2. Look up that hash to find where we saw those bytes before.
    #   3. If found, we might have a match (need to verify due to collisions).
    #
    # Table size is a power of 2 for fast modulo (bitwise AND).
    # Larger blocks get larger tables for better compression.
    table_bits = _compute_table_bits(len(block))
    table_size = 1 << table_bits
    table: list[int] = [-1] * table_size  # -1 = empty slot

    # Initialize compression state.
    output = bytearray()

    # - literal_start: where the current run of unmatched bytes began.
    # - ip (input pointer): current position we're examining.
    literal_start = 0
    ip = 0

    # Main compression loop.
    #
    # We stop INPUT_MARGIN_BYTES before the end to avoid bounds checks
    # in the inner loop. The remaining bytes are emitted as literals.
    while ip < len(block) - INPUT_MARGIN_BYTES:
        # Step 1: Hash the 4 bytes at current position.
        hash_val = _hash_4_bytes(block, ip, table_bits)

        # Step 2: Look up the hash to find a potential match.
        match_pos = table[hash_val]

        # Step 3: Update hash table with current position.
        #
        # Must happen AFTER lookup to avoid matching ourselves.
        table[hash_val] = ip

        # Step 4: Check if we found a real match.
        #
        # Two conditions:
        #   - match_pos >= 0: the slot wasn't empty
        #   - bytes actually match (hash collision check)
        if match_pos >= 0 and _matches_at(block, match_pos, ip):
            # Found a match!

            # First, emit any pending literals.
            # These are bytes between literal_start and ip that we couldn't match.
            if ip > literal_start:
                output.extend(_emit_literal(block[literal_start:ip]))

            # Extend the match as far as possible.
            # We know 4 bytes match (from the hash), but maybe more do too.
            match_length = _extend_match(block, match_pos, ip)

            # Emit the copy tag.
            # "Go back (ip - match_pos) bytes, copy match_length bytes."
            copy_offset = ip - match_pos
            output.extend(encode_copy_tag(match_length, copy_offset))

            # Advance past the matched region.
            ip += match_length
            literal_start = ip

            # Optimization: populate hash table for skipped positions.
            # This helps find matches that start inside the region we just copied.
            if match_length > 1 and ip < len(block) - INPUT_MARGIN_BYTES:
                for skip_pos in range(ip - match_length + 1, ip - 1, 2):
                    if skip_pos >= 0:
                        skip_hash = _hash_4_bytes(block, skip_pos, table_bits)
                        table[skip_hash] = skip_pos
        else:
            # No match found.
            #
            # Move to the next byte. It will be part of the literal run.
            ip += 1

    # Emit remaining bytes as literal.
    #
    # This includes:
    #   - The INPUT_MARGIN_BYTES we didn't process.
    #   - Any pending literal bytes from the last iteration.
    if literal_start < len(block):
        output.extend(_emit_literal(block[literal_start:]))

    return bytes(output)


def _compute_table_bits(block_size: int) -> int:
    """Compute hash table size (as power of 2) for a given block size.

    Args:
        block_size: Size of the block being compressed.

    Returns:
        Number of bits (table_size = 2^bits).

    Heuristic: ~1 slot per 4 input bytes.
    Clamped to [256, 16384] slots.
    """
    # Target: one hash slot per 4 bytes of input.
    target = block_size // 4

    # Find smallest power of 2 >= target.
    bits = MIN_HASH_TABLE_BITS
    while (1 << bits) < target and bits < MAX_HASH_TABLE_BITS:
        bits += 1

    return bits


def _hash_4_bytes(data: bytes, pos: int, table_bits: int) -> int:
    """Hash 4 bytes into a table index.

    Args:
        data: Input data.
        pos: Position of the 4 bytes to hash.
        table_bits: Number of bits in table index.

    Returns:
        Hash value in [0, 2^table_bits - 1].

    Algorithm:
        1. Read 4 bytes as little-endian uint32.
        2. Multiply by a magic constant (spreads bits).
        3. Take the TOP bits (better distribution than bottom bits).

    Example:
        data = b"ABCD", pos = 0, table_bits = 10

        Step 1: Read as little-endian uint32
            bytes: [0x41, 0x42, 0x43, 0x44]  (A, B, C, D)
            value = 0x41 | (0x42 << 8) | (0x43 << 16) | (0x44 << 24)
                  = 0x44434241
                  = 1145258561

        Step 2: Multiply by magic constant
            hash_val = (1145258561 * 0x1e35a7bd) & 0xFFFFFFFF
                     = 0x9E3779B9  (example result)

        Step 3: Take top 10 bits
            result = 0x9E3779B9 >> (32 - 10)
                   = 0x9E3779B9 >> 22
                   = 631  (table index)
    """
    # Read 4 bytes as little-endian uint32.
    #
    # Example: b"ABCD" at pos 0
    #   data[0] = 0x41 (A)
    #   data[1] = 0x42 (B)
    #   data[2] = 0x43 (C)
    #   data[3] = 0x44 (D)
    #   value = 0x44434241 (D C B A in memory order)
    value = data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24)

    # Multiply and mask to 32 bits.
    #
    # The magic constant (0x1e35a7bd) is chosen to spread input bits
    # across the output. This reduces collisions for similar inputs.
    # We mask to 32 bits because Python integers are arbitrary precision.
    hash_val = (value * HASH_MULTIPLIER) & 0xFFFFFFFF

    # Take top bits.
    #
    # Why top bits, not bottom?
    # The multiplication spreads information to the high bits.
    # Bottom bits are more affected by the low bits of the input,
    # which tend to be similar for nearby positions.
    return hash_val >> (32 - table_bits)


def _matches_at(data: bytes, pos1: int, pos2: int) -> bool:
    """Check if 4 bytes at pos1 equal 4 bytes at pos2.

    Args:
        data: Input data.
        pos1: First position.
        pos2: Second position.

    Returns:
        True if all 4 bytes match.

    Why is this needed?
        Hash collisions exist. Two different 4-byte sequences can have
        the same hash. This function verifies the match is real.

    Example:
        data = b"ABCDXXABCD"
        pos1 = 0, pos2 = 6

        data[0:4] = b"ABCD"
        data[6:10] = b"ABCD"
        Result: True (real match!)

    Counter-example (hash collision):
        Suppose hash("ABCD") == hash("WXYZ") (collision).
        The hash table might point us to "WXYZ", but:

        data[0:4] = b"WXYZ"
        data[6:10] = b"ABCD"
        Result: False (not a real match, just a hash collision)
    """
    return data[pos1 : pos1 + 4] == data[pos2 : pos2 + 4]


def _extend_match(data: bytes, match_pos: int, current_pos: int) -> int:
    """Extend a match as far as possible.

    Args:
        data: Input data.
        match_pos: Position of the earlier occurrence.
        current_pos: Current position.

    Returns:
        Total match length (minimum 4, maximum 64).

    We already know 4 bytes match (from hash lookup).
    This function checks how many MORE bytes also match.

    Example:
        data = b"ABCDEFGH....ABCDEFXY"
        match_pos = 0, current_pos = 12

        We know data[0:4] == data[12:16] (both "ABCD").

        Now we check byte by byte:
            data[0+4] = 'E', data[12+4] = 'E' -> match! length = 5
            data[0+5] = 'F', data[12+5] = 'F' -> match! length = 6
            data[0+6] = 'G', data[12+6] = 'X' -> no match, stop.

        Result: 6 bytes can be copied.
    """
    # Start with the 4 bytes we already verified.
    length = 4

    # Maximum copy length is 64 (Snappy format limit).
    max_length = 64

    # Extend while bytes continue to match.
    #
    # We compare one byte at a time:
    #   data[match_pos + length] vs data[current_pos + length]
    #
    # Stop when:
    #   - We hit the max length (64), or
    #   - We reach end of data, or
    #   - Bytes don't match.
    while (
        length < max_length
        and current_pos + length < len(data)
        and data[match_pos + length] == data[current_pos + length]
    ):
        length += 1

    return length


def _emit_literal(literal_data: bytes) -> bytes:
    """Encode literal data (unmatched bytes).

    Args:
        literal_data: Raw bytes to emit.

    Returns:
        Encoded literal: [tag] [raw bytes].

    Literals are bytes that couldn't be matched to earlier data.
    They're stored as-is, with a tag prefix indicating the length.

    Example:
        literal_data = b"Hello" (5 bytes)

        The tag encodes the length (5).
        For short literals (1-60 bytes), the tag is 1 byte:
            tag = (length - 1) << 2 | 0b00
                = (5 - 1) << 2 | 0
                = 4 << 2
                = 0x10

        Output: [0x10, 'H', 'e', 'l', 'l', 'o']
                 ^tag   ^---- raw bytes ----^

        The decompressor reads the tag, extracts length = (0x10 >> 2) + 1 = 5,
        then copies the next 5 bytes to output.
    """
    if not literal_data:
        return b""

    return bytes(encode_literal_tag(len(literal_data))) + literal_data
