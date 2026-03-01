"""
Encoding utilities for the Snappy compression format.

This module provides the low-level encoding and decoding primitives used by
both the compressor and decompressor:

1. **Varint encoding**: Variable-length integer encoding for the uncompressed
   length prefix. Small values use fewer bytes, saving space.

2. **Tag byte encoding**: Compact representation of literal and copy operations.
   The tag byte format packs operation type and length into minimal space.

Reference: https://github.com/google/snappy/blob/main/format_description.txt
"""

from __future__ import annotations

from typing import Literal

from .constants import (
    COPY_1_BYTE_OFFSET,
    COPY_2_BYTE_OFFSET,
    COPY_4_BYTE_OFFSET,
    LITERAL,
    LITERAL_LENGTH_1_BYTE,
    LITERAL_LENGTH_2_BYTES,
    LITERAL_LENGTH_3_BYTES,
    LITERAL_LENGTH_4_BYTES,
    MAX_COPY_1_LENGTH,
    MAX_COPY_1_OFFSET,
    MAX_COPY_2_OFFSET,
    MAX_INLINE_LITERAL_LENGTH,
    MIN_COPY_1_LENGTH,
    VARINT_CONTINUATION_BIT,
    VARINT_DATA_MASK,
)

type TagType = Literal["literal", "copy"]
"""Snappy tag type: either a literal (raw bytes) or a copy (back-reference)."""

# Varint Encoding
#
# Varints encode integers using as few bytes as possible.
#   - Small values use fewer bytes.
#   - Large values use more.
#
# Each byte has 8 bits:
#   - Bit 7 (high): continuation flag.
#       - 1 = more bytes follow,
#       - 0 = this is the last byte.
#   - Bits 0-6 (low): 7 bits of the integer value.
#
# Bytes are emitted least-significant chunk first.
#
# Byte count by value:
#   0 .. 127                  -> 1 byte
#   128 .. 16,383             -> 2 bytes
#   16,384 .. 2,097,151       -> 3 bytes
#   2,097,152 .. 268,435,455  -> 4 bytes
#   268,435,456 .. 2^32 - 1   -> 5 bytes
#
# Example: encoding 300
#
#   300 in binary: 100101100 (9 bits, needs 2 chunks of 7 bits)
#
#   Chunk 1 (bits 0-6): 0101100 = 44. More bits remain, so continuation = 1.
#       Byte 1 = 0x80 | 44 = 0xAC
#
#   Chunk 2 (bits 7+): 0000010 = 2. No more bits, so continuation = 0.
#       Byte 2 = 0x00 | 2 = 0x02
#
#   Encoded: [0xAC, 0x02]
#
# Example: decoding [0xAC, 0x02]
#
#   For each byte: check bit 7 for continuation, mask with 0x7F to get data.
#
#   Byte 1 = 0xAC = 10101100:
#       bit 7 = 1 -> more bytes coming
#       data  = 0xAC & 0x7F = 0101100 = 44
#       result = 44
#
#   Byte 2 = 0x02 = 00000010:
#       bit 7 = 0 -> done
#       data  = 0x02 & 0x7F = 0000010 = 2 (mask has no effect here)
#       result = 44 | (2 << 7) = 44 + 256 = 300


def encode_varint32(value: int) -> bytes:
    """Encode a 32-bit integer as a variable-length byte sequence.

    The varint format uses 7 bits per byte for data, with the high bit
    indicating whether more bytes follow. This efficiently encodes small
    values in fewer bytes.

    Algorithm:
    1. Take the lowest 7 bits of the value.
    2. If more bits remain, set the continuation bit (0x80).
    3. Repeat until all bits are encoded.

    Args:
        value: Non-negative integer to encode (must fit in 32 bits).

    Returns:
        Variable-length bytes encoding the integer (1-5 bytes).

    Raises:
        ValueError: If value is negative or exceeds 32 bits.
    """
    # Validate input range.
    # Varints in Snappy are unsigned 32-bit integers.
    if value < 0:
        raise ValueError(f"Varint value must be non-negative, got {value}")
    if value > 0xFFFFFFFF:
        raise ValueError(f"Varint value exceeds 32 bits: {value}")

    # Build the encoding byte by byte.
    # We accumulate bytes in a list for efficiency.
    result: list[int] = []

    while True:
        # Extract the lowest 7 bits.
        byte = value & VARINT_DATA_MASK

        # Shift out the bits we just encoded.
        value >>= 7

        if value != 0:
            # More bits remain: set continuation bit.
            byte |= VARINT_CONTINUATION_BIT

        result.append(byte)

        if value == 0:
            # All bits encoded.
            break

    return bytes(result)


def decode_varint32(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a varint from a byte sequence at the given offset.

    Reads bytes starting at offset, accumulating 7 bits per byte into
    the result. Stops when a byte without the continuation bit is found.

    Args:
        data: Byte sequence containing the varint.
        offset: Position in data where the varint starts.

    Returns:
        Tuple of (decoded_value, bytes_consumed).

    Raises:
        ValueError: If the varint is malformed (too long or truncated).
    """
    result = 0
    shift = 0
    bytes_read = 0

    while True:
        # Check bounds.
        if offset + bytes_read >= len(data):
            raise ValueError("Truncated varint: unexpected end of data")

        # Read next byte.
        byte = data[offset + bytes_read]
        bytes_read += 1

        # Accumulate the 7 data bits at the current shift position.
        result |= (byte & VARINT_DATA_MASK) << shift
        shift += 7

        # Check if this is the last byte (no continuation bit).
        if (byte & VARINT_CONTINUATION_BIT) == 0:
            break

        # Safety check: varints should not exceed 5 bytes for 32-bit values.
        # (5 bytes * 7 bits = 35 bits, which covers 32-bit range)
        if bytes_read >= 5:
            raise ValueError("Varint too long: exceeds 5 bytes")

    # Verify the result fits in 32 bits.
    if result > 0xFFFFFFFF:
        raise ValueError(f"Varint overflow: {result} exceeds 32 bits")

    return result, bytes_read


# Tag Byte Encoding - Literals
#
# Literals are raw bytes that couldn't be compressed (no match found).
# A literal tag tells the decoder: "copy the next N bytes as-is".
#
# Tag byte structure:
#   - Bits 0-1: type = 00 (LITERAL)
#   - Bits 2-7: length info (6 bits, values 0-63)
#
# The 6-bit length info determines the format:
#
#   Value 0-59:  length is stored inline.
#       Length = value + 1 (so 1-60 bytes).
#       Total: 1 tag byte, then literal data.
#
#   Value 60:    length stored in 1 extra byte.
#       Length = next_byte + 1 (so 1-256 bytes).
#       Total: 1 tag byte + 1 length byte, then literal data.
#
#   Value 61:    length stored in 2 extra bytes (little-endian).
#       Length = uint16 + 1 (so 1-65536 bytes).
#       Total: 1 tag byte + 2 length bytes, then literal data.
#
#   Value 62:    length stored in 3 extra bytes (little-endian).
#   Value 63:    length stored in 4 extra bytes (little-endian).
#
# Example: literal of 10 bytes
#
#   Length = 10, so length info = 10 - 1 = 9 (fits in 0-59 range).
#   Tag byte = (9 << 2) | 0b00 = 0b00100100 = 0x24
#   Output: [0x24] followed by 10 literal bytes.
#
# Example: literal of 200 bytes
#
#   Length = 200, too big for inline (max 60).
#   Use length info = 60, store (200 - 1) = 199 in next byte.
#   Tag byte = (60 << 2) | 0b00 = 0b11110000 = 0xF0
#   Output: [0xF0, 0xC7] followed by 200 literal bytes.


def encode_literal_tag(length: int) -> bytes:
    """Encode a literal tag for the given data length.

    Returns the tag byte(s) that should precede literal data in the
    compressed stream. The actual literal bytes follow immediately.

    Args:
        length: Number of literal bytes (must be >= 1).

    Returns:
        Tag bytes (1-5 bytes depending on length).

    Raises:
        ValueError: If length is less than 1 or too large.
    """
    if length < 1:
        raise ValueError(f"Literal length must be >= 1, got {length}")

    if length <= MAX_INLINE_LITERAL_LENGTH:
        # Short literal: encode (length - 1) in upper 6 bits of tag.
        # Format: [length-1 (6 bits)][LITERAL (2 bits)]
        tag = ((length - 1) << 2) | LITERAL
        return bytes([tag])

    elif length <= 256:
        # Medium literal: tag indicates 1-byte length follows.
        # Format: [60 (6 bits)][LITERAL (2 bits)] + [length-1 (8 bits)]
        tag = (LITERAL_LENGTH_1_BYTE << 2) | LITERAL
        return bytes([tag, length - 1])

    elif length <= 65536:
        # Large literal: tag indicates 2-byte length follows.
        # Format: [61 (6 bits)][LITERAL (2 bits)] + [length-1 (16 bits LE)]
        tag = (LITERAL_LENGTH_2_BYTES << 2) | LITERAL
        len_minus_1 = length - 1
        return bytes([tag, len_minus_1 & 0xFF, (len_minus_1 >> 8) & 0xFF])

    elif length <= 16777216:
        # Very large literal: tag indicates 3-byte length follows.
        # Format: [62 (6 bits)][LITERAL (2 bits)] + [length-1 (24 bits LE)]
        tag = (LITERAL_LENGTH_3_BYTES << 2) | LITERAL
        len_minus_1 = length - 1
        return bytes(
            [
                tag,
                len_minus_1 & 0xFF,
                (len_minus_1 >> 8) & 0xFF,
                (len_minus_1 >> 16) & 0xFF,
            ]
        )

    elif length <= 4294967296:
        # Maximum literal: tag indicates 4-byte length follows.
        # Format: [63 (6 bits)][LITERAL (2 bits)] + [length-1 (32 bits LE)]
        tag = (LITERAL_LENGTH_4_BYTES << 2) | LITERAL
        len_minus_1 = length - 1
        return bytes(
            [
                tag,
                len_minus_1 & 0xFF,
                (len_minus_1 >> 8) & 0xFF,
                (len_minus_1 >> 16) & 0xFF,
                (len_minus_1 >> 24) & 0xFF,
            ]
        )

    else:
        raise ValueError(f"Literal length too large: {length}")


# Tag Byte Encoding - Copies
#
# Copies are backreferences to already-decompressed data.
# A copy tag tells the decoder: "go back OFFSET bytes, copy LENGTH bytes".
#
# Tag byte structure (bits 0-1 determine the type):
#   - 01 = copy type 1 (short, 2 bytes total)
#   - 10 = copy type 2 (medium, 3 bytes total)
#   - 11 = copy type 4 (long, 5 bytes total)
#
# Note: there is no copy type 3. The types are named after their byte count
# minus the tag byte (1, 2, or 4 extra bytes for the offset).
#
#
# COPY TYPE 1 (2 bytes total)
# ---------------------------
# Most compact. For short offsets and small lengths.
#   - Offset: 1 to 2048 (11 bits: 3 in tag, 8 in next byte)
#   - Length: 4 to 11 (3 bits store length - 4)
#
# Tag byte layout:
#   - Bits 0-1: 01 (copy type 1)
#   - Bits 2-4: length - 4 (values 0-7, meaning lengths 4-11)
#   - Bits 5-7: offset high bits (bits 8-10 of offset)
# Next byte: offset low bits (bits 0-7 of offset)
#
# Bit Position:  7   6   5   4   3   2   1   0
#              +---+---+---+---+---+---+---+---+
# Function:    | O   O   O | L   L   L | 0   1 |
#              +---+---+---+---+---+---+---+---+
#                ^           ^           ^
#                |           |           Type ID (Fixed 01)
#                |           |
#                |           Length Component (3 bits)
#                |           Value = Length - 4
#                |
#                Offset Component (High 3 bits)
#                Bits 8, 9, 10 of the Offset
#
# Example: copy 6 bytes from offset 300 (0x12C)
#
# 1. PREPARE THE VALUES
#    We use Copy Type 1 because:
#       - the offset (300) is small (< 2048),
#       - the length (6) is small (< 12).
#
#    A. Length Code:
#       Format stores (Length - 4).
#       6 - 4 = 2.
#       Binary: 010
#
#    B. Offset Split:
#       Offset 300 is 0x12C (binary: 001 0010 1100).
#       It requires 11 bits. We split it into two parts:
#       - High (Top 3 bits):    001 (Decimal 1) -> Goes into Tag Byte
#       - Low  (Bottom 8 bits): 0010 1100 (Hex 0x2C) -> Goes into Next Byte
#
# 2. BUILD THE TAG BYTE
#    We pack three components into one byte using bit shifts:
#    - Bits 0-1: Type ID (01)       -> 01
#    - Bits 2-4: Length Code (2)    -> 010 << 2  = 00001000
#    - Bits 5-7: Offset High (1)    -> 001 << 5  = 00100000
#
#    Combine (OR): 00100000 | 00001000 | 01 = 00101001
#    Result Hex:   0x29
#
# 3. FINAL OUTPUT
#    Byte 1: Tag (0x29)
#    Byte 2: Offset Low (0x2C)
#    Output: [0x29, 0x2C]
#
#
# COPY TYPE 2 (3 bytes total)
# ---------------------------
# For medium offsets. More flexible length range.
#   - Offset: 1 to 65535 (16 bits in next 2 bytes)
#   - Length: 1 to 64 (6 bits store length - 1)
#
# Tag byte layout:
#   - Bits 0-1: 10 (copy type 2)
#   - Bits 2-7: length - 1 (values 0-63, meaning lengths 1-64)
# Next 2 bytes: offset as little-endian uint16
#
# Bit Position:  7   6   5   4   3   2   1   0
#              +---+---+---+---+---+---+---+---+
# Function:    | L   L   L   L   L   L | 1   0 |
#              +---+---+---+---+---+---+---+---+
#                ^                       ^
#                |                       Type ID (Fixed 10)
#                |
#                Length Component (6 bits)
#                Value = Length - 1
#
# Example: copy 20 bytes from offset 1000 (0x03E8)
#
# 1. PREPARE THE VALUES
#    We use Copy Type 2 here. Even though the offset (1000) fits in Type 1,
#    the length (20) is too large (Type 1 max length is 11).
#
#    A. Length Code:
#       Format stores (Length - 1).
#       20 - 1 = 19.
#       Binary: 010011
#
#    B. Offset (Little Endian):
#       Offset 1000 is 0x03E8 in Hexadecimal.
#       Copy Type 2 uses a standard 2-byte integer for the offset.
#       Snappy uses "Little Endian" order (Least Significant Byte first).
#       - Low Byte (00xx):  0xE8
#       - High Byte (xx00): 0x03
#
# 2. BUILD THE TAG BYTE
#    We pack the Length and Type ID into the first byte:
#    - Bits 0-1: Type ID (10)       -> 10 (Binary)
#    - Bits 2-7: Length Code (19)   -> 19 in binary is 010011
#                                      Shift left by 2: 01001100
#
#    Combine (OR): 01001100 | 10 = 01001110
#    Result Hex:   0x4E
#
# 3. FINAL OUTPUT
#    Byte 1: Tag (0x4E)
#    Byte 2: Offset Low  (0xE8)
#    Byte 3: Offset High (0x03)
#    Output: [0x4E, 0xE8, 0x03]
#
#
# COPY TYPE 4 (5 bytes total)
# ---------------------------
# For long offsets (large files).
#   - Offset: 1 to 2^32 - 1 (32 bits in next 4 bytes)
#   - Length: 1 to 64 (6 bits store length - 1)
#
# Tag byte layout:
#   - Bits 0-1: 11 (copy type 4)
#   - Bits 2-7: length - 1 (values 0-63, meaning lengths 1-64)
# Next 4 bytes: offset as little-endian uint32
#
# Bit Position:  7   6   5   4   3   2   1   0
#              +---+---+---+---+---+---+---+---+
# Function:    | L   L   L   L   L   L | 1   1 |
#              +---+---+---+---+---+---+---+---+
#                ^                       ^
#                |                       Type ID (Fixed 11)
#                |
#                Length Component (6 bits)
#                Value = Length - 1


def encode_copy_tag(length: int, offset: int) -> bytes:
    """Encode a copy tag for the given length and offset.

    Automatically selects the most compact encoding based on the
    offset and length values.

    Args:
        length: Number of bytes to copy (must be >= 1).
        offset: Backward offset to copy from (must be >= 1).

    Returns:
        Tag bytes (2, 3, or 5 bytes depending on offset/length).

    Raises:
        ValueError: If length or offset is out of valid range.
    """
    if length < 1:
        raise ValueError(f"Copy length must be >= 1, got {length}")
    if offset < 1:
        raise ValueError(f"Copy offset must be >= 1, got {offset}")

    # Try copy type 1 first: most compact for short offsets and lengths.
    # Requirements: offset <= 2047, length in [4, 11]
    if offset <= MAX_COPY_1_OFFSET and MIN_COPY_1_LENGTH <= length <= MAX_COPY_1_LENGTH:
        return _encode_copy_1(length, offset)

    # Try copy type 2: good for medium offsets.
    # Requirements: offset <= 65535, length in [1, 64]
    if offset <= MAX_COPY_2_OFFSET and length <= 64:
        return _encode_copy_2(length, offset)

    # Fall back to copy type 4: handles any offset up to 4GB.
    # Requirements: length in [1, 64]
    if length <= 64:
        return _encode_copy_4(length, offset)

    # Length > 64 requires multiple copy operations.
    raise ValueError(f"Copy length too large for single tag: {length}")


def _encode_copy_1(length: int, offset: int) -> bytes:
    """Encode a copy-1 tag (2 bytes).

    Format:
      Tag byte: [offset_high (3 bits)][length-4 (3 bits)][01 (2 bits)]
      Byte 2:   [offset_low (8 bits)]

    The offset is split: high 3 bits in tag, low 8 bits in next byte.
    This gives 11 bits total = offsets up to 2047.
    """
    # Split offset into high (3 bits) and low (8 bits) parts.
    offset_low = offset & 0xFF
    offset_high = (offset >> 8) & 0x07  # Top 3 bits

    # Build tag byte:
    # - Bits 7-5: offset_high (3 bits)
    # - Bits 4-2: length - 4 (3 bits, since length is 4-11)
    # - Bits 1-0: COPY_1_BYTE_OFFSET (01)
    tag = (offset_high << 5) | ((length - 4) << 2) | COPY_1_BYTE_OFFSET

    return bytes([tag, offset_low])


def _encode_copy_2(length: int, offset: int) -> bytes:
    """Encode a copy-2 tag (3 bytes).

    Format:
      Tag byte: [length-1 (6 bits)][10 (2 bits)]
      Bytes 2-3: offset as little-endian uint16
    """
    tag = ((length - 1) << 2) | COPY_2_BYTE_OFFSET
    return bytes([tag, offset & 0xFF, (offset >> 8) & 0xFF])


def _encode_copy_4(length: int, offset: int) -> bytes:
    """Encode a copy-4 tag (5 bytes).

    Format:
      Tag byte: [length-1 (6 bits)][11 (2 bits)]
      Bytes 2-5: offset as little-endian uint32
    """
    tag = ((length - 1) << 2) | COPY_4_BYTE_OFFSET
    return bytes(
        [
            tag,
            offset & 0xFF,
            (offset >> 8) & 0xFF,
            (offset >> 16) & 0xFF,
            (offset >> 24) & 0xFF,
        ]
    )


# Tag Decoding
#
# Decoding is the inverse of encoding.
# Given a compressed stream, we parse tags to reconstruct the original data.
#
# Step 1: Read the tag byte.
# Step 2: Check bits 0-1 to determine the type.
# Step 3: Extract length (and offset for copies) based on the type.
# Step 4: Perform the operation (copy literal bytes, or copy from history).
#
# Type identification (bits 0-1 of tag byte):
#   00 = Literal
#   01 = Copy Type 1
#   10 = Copy Type 2
#   11 = Copy Type 4
#
#
# DECODING A LITERAL
# ------------------
# 1. Read bits 2-7 of the tag byte (the "length indicator").
# 2. If indicator < 60: length = indicator + 1. Done.
# 3. If indicator >= 60: read (indicator - 59) extra bytes as length - 1.
#
# Example: decode tag byte 0x24
#   Tag = 0x24 = 0b00100100
#   Bits 0-1 = 00 -> Literal
#   Bits 2-7 = 001001 = 9 -> length indicator
#   Since 9 < 60: length = 9 + 1 = 10 bytes
#   Result: read 10 literal bytes from the stream.
#
#
# DECODING COPY TYPE 1
# --------------------
# 1. Extract length: bits 2-4 of tag, add 4.
# 2. Extract offset: bits 5-7 of tag (high), next byte (low).
#
# Example: decode [0x29, 0x2C]
#   Tag = 0x29 = 0b00101001
#   Bits 0-1 = 01 -> Copy Type 1
#   Bits 2-4 = 010 = 2 -> length = 2 + 4 = 6
#   Bits 5-7 = 001 = 1 -> offset high
#   Next byte = 0x2C = 44 -> offset low
#   Offset = (1 << 8) | 44 = 256 + 44 = 300
#   Result: copy 6 bytes from 300 bytes back.
#
#
# DECODING COPY TYPE 2
# --------------------
# 1. Extract length: bits 2-7 of tag, add 1.
# 2. Read next 2 bytes as little-endian offset.
#
# Example: decode [0x4E, 0xE8, 0x03]
#   Tag = 0x4E = 0b01001110
#   Bits 0-1 = 10 -> Copy Type 2
#   Bits 2-7 = 010011 = 19 -> length = 19 + 1 = 20
#   Next 2 bytes = [0xE8, 0x03] -> offset = 0xE8 | (0x03 << 8) = 1000
#   Result: copy 20 bytes from 1000 bytes back.
#
#
# DECODING COPY TYPE 4
# --------------------
# 1. Extract length: bits 2-7 of tag, add 1.
# 2. Read next 4 bytes as little-endian offset.
#
# Same as Copy Type 2, but with a 32-bit offset for large files.


def decode_tag(data: bytes, offset: int = 0) -> tuple[TagType, int, int, int]:
    """Decode a tag at the given offset in the data.

    Parses the tag byte and any following length/offset bytes to determine
    the operation type, data length, and for copies, the backward offset.

    Args:
        data: Compressed data containing the tag.
        offset: Position of the tag byte in data.

    Returns:
        Tuple of (tag_type, length, copy_offset, bytes_consumed).
        - tag_type: "literal" or "copy"
        - length: Number of bytes (literal data or copy length)
        - copy_offset: For copies, the backward offset; 0 for literals
        - bytes_consumed: Total bytes read for this tag

    Raises:
        ValueError: If the tag is malformed or data is truncated.
    """
    if offset >= len(data):
        raise ValueError("No tag byte at offset")

    tag = data[offset]
    tag_type = tag & 0x03  # Lower 2 bits determine type

    if tag_type == LITERAL:
        return _decode_literal_tag(data, offset, tag)
    elif tag_type == COPY_1_BYTE_OFFSET:
        return _decode_copy_1_tag(data, offset, tag)
    elif tag_type == COPY_2_BYTE_OFFSET:
        return _decode_copy_2_tag(data, offset, tag)
    else:  # COPY_4_BYTE_OFFSET
        return _decode_copy_4_tag(data, offset, tag)


def _decode_literal_tag(data: bytes, offset: int, tag: int) -> tuple[TagType, int, int, int]:
    """Decode a literal tag and return (type, length, 0, bytes_consumed)."""
    # Upper 6 bits encode the length indicator.
    length_indicator = tag >> 2

    if length_indicator < LITERAL_LENGTH_1_BYTE:
        # Inline length: length = indicator + 1
        return ("literal", length_indicator + 1, 0, 1)

    elif length_indicator == LITERAL_LENGTH_1_BYTE:
        # 1 additional byte for length.
        if offset + 1 >= len(data):
            raise ValueError("Truncated literal tag: expected 1 length byte")
        length = data[offset + 1] + 1
        return ("literal", length, 0, 2)

    elif length_indicator == LITERAL_LENGTH_2_BYTES:
        # 2 additional bytes for length (little-endian).
        if offset + 2 >= len(data):
            raise ValueError("Truncated literal tag: expected 2 length bytes")
        length = data[offset + 1] | (data[offset + 2] << 8)
        return ("literal", length + 1, 0, 3)

    elif length_indicator == LITERAL_LENGTH_3_BYTES:
        # 3 additional bytes for length (little-endian).
        if offset + 3 >= len(data):
            raise ValueError("Truncated literal tag: expected 3 length bytes")
        length = data[offset + 1] | (data[offset + 2] << 8) | (data[offset + 3] << 16)
        return ("literal", length + 1, 0, 4)

    else:  # LITERAL_LENGTH_4_BYTES
        # 4 additional bytes for length (little-endian).
        if offset + 4 >= len(data):
            raise ValueError("Truncated literal tag: expected 4 length bytes")
        length = (
            data[offset + 1]
            | (data[offset + 2] << 8)
            | (data[offset + 3] << 16)
            | (data[offset + 4] << 24)
        )
        return ("literal", length + 1, 0, 5)


def _decode_copy_1_tag(data: bytes, offset: int, tag: int) -> tuple[TagType, int, int, int]:
    """Decode a copy-1 tag and return (type, length, offset, bytes_consumed)."""
    if offset + 1 >= len(data):
        raise ValueError("Truncated copy-1 tag: expected offset byte")

    # Extract length: bits 4-2 encode (length - 4), so length is in [4, 11].
    length = ((tag >> 2) & 0x07) + 4

    # Extract offset: high 3 bits from tag, low 8 bits from next byte.
    offset_high = (tag >> 5) & 0x07
    offset_low = data[offset + 1]
    copy_offset = (offset_high << 8) | offset_low

    return ("copy", length, copy_offset, 2)


def _decode_copy_2_tag(data: bytes, offset: int, tag: int) -> tuple[TagType, int, int, int]:
    """Decode a copy-2 tag and return (type, length, offset, bytes_consumed)."""
    if offset + 2 >= len(data):
        raise ValueError("Truncated copy-2 tag: expected 2 offset bytes")

    # Length is in upper 6 bits: (length - 1).
    length = (tag >> 2) + 1

    # Offset is little-endian uint16 in next 2 bytes.
    copy_offset = data[offset + 1] | (data[offset + 2] << 8)

    return ("copy", length, copy_offset, 3)


def _decode_copy_4_tag(data: bytes, offset: int, tag: int) -> tuple[TagType, int, int, int]:
    """Decode a copy-4 tag and return (type, length, offset, bytes_consumed)."""
    if offset + 4 >= len(data):
        raise ValueError("Truncated copy-4 tag: expected 4 offset bytes")

    # Length is in upper 6 bits: (length - 1).
    length = (tag >> 2) + 1

    # Offset is little-endian uint32 in next 4 bytes.
    copy_offset = (
        data[offset + 1]
        | (data[offset + 2] << 8)
        | (data[offset + 3] << 16)
        | (data[offset + 4] << 24)
    )

    return ("copy", length, copy_offset, 5)
