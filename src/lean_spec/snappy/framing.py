"""
Snappy framing format for streaming compression.

This module implements the Snappy framing format, a wrapper around raw Snappy
that enables streaming and adds CRC32C checksums for error detection.


WHY FRAMING?
------------
Raw Snappy compresses a single block of data. For network protocols, we need:

  1. STREAMING: Process data in chunks without buffering everything.
  2. ERROR DETECTION: Detect corruption during transmission.
  3. CONCATENATION: Combine multiple compressed streams.

The framing format solves all three by wrapping raw Snappy in checksummed chunks.


STREAM STRUCTURE
----------------
A framed stream consists of chunks laid back-to-back::

    [stream_identifier][chunk_1][chunk_2]...[chunk_n]

The stream MUST start with a stream identifier. There is no end-of-stream
marker; the stream ends when the data ends.


STREAM IDENTIFIER (10 bytes)
----------------------------
Every stream starts with::

    0xff 0x06 0x00 0x00 's' 'N' 'a' 'P' 'p' 'Y'

Breakdown:
  - 0xff: Chunk type (stream identifier)
  - 0x06 0x00 0x00: Chunk length = 6 (little-endian)
  - "sNaPpY": Magic bytes

This identifier can appear multiple times (e.g., concatenated streams).


CHUNK FORMAT
------------
Each chunk has a 4-byte header followed by data::

    [type: 1 byte][length: 3 bytes LE][data: length bytes]

The length field does NOT include the 4-byte header itself.


CHUNK TYPES
-----------
  0x00: Compressed data
        [crc32c: 4 bytes][snappy_compressed_data]
        CRC covers the UNCOMPRESSED data.

  0x01: Uncompressed data
        [crc32c: 4 bytes][raw_data]
        Used when compression would expand the data.

  0xff: Stream identifier (see above)

  0x02-0x7f: Reserved unskippable (must error if encountered)

  0x80-0xfe: Reserved skippable (must skip silently)


CRC32C MASKING
--------------
CRCs are stored "masked" to detect common corruptions::

    masked = rotate_right(crc, 15) + 0xA282EAD8

This detects patterns like all-zeros that might not affect an unmasked CRC.


SIZE LIMITS
-----------
Each chunk's uncompressed data must be at most 65536 bytes (64 KiB).
This allows decompressors to use fixed-size buffers.


Reference:
    https://github.com/google/snappy/blob/master/framing_format.txt
"""

from __future__ import annotations

from .compress import compress as raw_compress
from .decompress import SnappyDecompressionError
from .decompress import decompress as raw_decompress

STREAM_IDENTIFIER: bytes = b"\xff\x06\x00\x00sNaPpY"
"""Stream identifier marking the start of a Snappy framed stream.

Format: [type=0xff][length=6 as 3-byte LE][magic="sNaPpY"]

This 10-byte sequence MUST appear at the start of every framed stream.
It may also appear later (e.g., when streams are concatenated).
"""

CHUNK_TYPE_COMPRESSED: int = 0x00
"""Chunk type for Snappy-compressed data.

Chunk data format: [masked_crc32c: 4 bytes LE][compressed_payload]
The CRC covers the UNCOMPRESSED data, not the compressed payload.
"""

CHUNK_TYPE_UNCOMPRESSED: int = 0x01
"""Chunk type for uncompressed (raw) data.

Chunk data format: [masked_crc32c: 4 bytes LE][raw_payload]
Used when compression would expand the data (e.g., random bytes).
"""

MAX_UNCOMPRESSED_CHUNK_SIZE: int = 65536
"""Maximum uncompressed data per chunk (64 KiB).

This limit enables fixed-size decompression buffers.
Chunks exceeding this limit are rejected.
"""

CRC32C_MASK_DELTA: int = 0xA282EAD8
"""Constant added during CRC masking.

From the spec: "Rotate right by 15 bits, then add 0xa282ead8."
This value is from Apache Hadoop's CRC masking scheme.
"""


# =============================================================================
# CRC32C Implementation
# =============================================================================
#
# CRC32C uses the Castagnoli polynomial (0x1EDC6F41), which has better error
# detection properties than the standard CRC32 polynomial.
#
# We use a lookup table for efficiency. Each byte lookup replaces 8 XOR/shift
# operations with a single table access.


def _crc32c_table() -> list[int]:
    """
    Generate the CRC32C lookup table.

    Uses the Castagnoli polynomial 0x82F63B78 (bit-reversed form of 0x1EDC6F41).

    Returns:
        256-entry lookup table for byte-at-a-time CRC computation.

    Algorithm:
        For each possible byte value (0-255):
          1. Start with the byte value as the CRC.
          2. For each of the 8 bits:
             - If LSB is 1: shift right and XOR with polynomial.
             - If LSB is 0: just shift right.
          3. Store final value in table.
    """
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            # Process one bit: if LSB is set, XOR with polynomial.
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F63B78
            else:
                crc >>= 1
        table.append(crc)
    return table


# Pre-compute the table at module load time.
_CRC32C_TABLE: list[int] = _crc32c_table()


def _crc32c(data: bytes) -> int:
    r"""
    Compute CRC32C checksum of data.

    Args:
        data: Input bytes.

    Returns:
        32-bit CRC32C checksum.

    Algorithm:
        1. Initialize CRC to all 1s (0xFFFFFFFF).
        2. For each byte: XOR with CRC, look up in table, XOR result with CRC>>8.
        3. Invert final CRC (XOR with 0xFFFFFFFF).
    """
    # Step 1: Initialize to all 1s.
    crc = 0xFFFFFFFF

    # Step 2: Process each byte using the lookup table.
    #
    # The table lookup combines 8 bit operations into one:
    #   index = (crc ^ byte) & 0xFF     <- low byte determines table entry
    #   crc = table[index] ^ (crc >> 8) <- combine with shifted CRC
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)

    # Step 3: Invert the final value.
    return crc ^ 0xFFFFFFFF


def _mask_crc(crc: int) -> int:
    """
    Mask a CRC32C for storage in Snappy frames.

    Args:
        crc: Raw CRC32C checksum.

    Returns:
        Masked CRC value.

    Why mask?
        Certain corruption patterns (all zeros, all ones) might not change
        an unmasked CRC. Masking transforms the CRC to detect these patterns.

    Formula (from spec):
        masked = rotate_right(crc, 15) + 0xa282ead8

    In bit operations:
        rotate_right(x, 15) = (x >> 15) | (x << 17)
    """
    # - Rotate right by 15 bits = shift right 15, OR with shift left 17.
    # - Add the mask delta constant.
    # - Mask to 32 bits (Python integers are arbitrary precision).
    return (((crc >> 15) | (crc << 17)) + CRC32C_MASK_DELTA) & 0xFFFFFFFF


def frame_compress(data: bytes) -> bytes:
    """
    Compress data using Snappy framing format.

    This is the compression format required by Ethereum's req/resp protocol.
    Data is split into chunks of at most 64 KiB, each independently compressed.

    Args:
        data: Uncompressed input bytes.

    Returns:
        Snappy framed stream ready for transmission.

    Output format::

        [stream_identifier: 10 bytes]
        [chunk_1: type + length + crc + payload]
        [chunk_2: type + length + crc + payload]
        ...

    Each chunk is either:
      - Compressed (0x00): When compression reduces size.
      - Uncompressed (0x01): When compression would expand data.
    """
    # Step 1: Start with stream identifier.
    #
    # Every framed stream MUST begin with this 10-byte magic sequence.
    # It identifies the format and allows stream concatenation.
    output = bytearray(STREAM_IDENTIFIER)

    # Step 2: Process input in chunks.
    #
    # We split input into chunks of at most 64 KiB. Each chunk is compressed
    # independently, allowing the decompressor to use fixed-size buffers.
    offset = 0
    while offset < len(data):
        # Extract next chunk (up to 64 KiB).
        chunk_end = min(offset + MAX_UNCOMPRESSED_CHUNK_SIZE, len(data))
        chunk = data[offset:chunk_end]
        offset = chunk_end

        # Compress the chunk using raw Snappy.
        compressed = raw_compress(chunk)

        # Compute CRC of UNCOMPRESSED data.
        #
        # Important: The CRC covers the original data, not the compressed form.
        # This allows verification after decompression.
        crc = _mask_crc(_crc32c(chunk))

        # Choose chunk type based on compression effectiveness.
        #
        # If compression expanded the data (e.g., random bytes), store raw.
        # This ensures the framed output is never larger than necessary.
        if len(compressed) < len(chunk):
            chunk_type = CHUNK_TYPE_COMPRESSED
            payload = compressed
        else:
            chunk_type = CHUNK_TYPE_UNCOMPRESSED
            payload = chunk

        # Build chunk: [type: 1][length: 3 LE][crc: 4 LE][payload].
        #
        # The length field includes CRC (4 bytes) + payload.
        # It does NOT include the 4-byte header (type + length).
        chunk_length = 4 + len(payload)
        output.append(chunk_type)
        output.extend(chunk_length.to_bytes(3, "little"))
        output.extend(crc.to_bytes(4, "little"))
        output.extend(payload)

    return bytes(output)


def frame_decompress(data: bytes) -> bytes:
    """
    Decompress Snappy framed data.

    Validates the stream structure and CRC32C checksums for each chunk.
    Corrupted or malformed streams raise SnappyDecompressionError.

    Args:
        data: Snappy framed stream.

    Returns:
        Original uncompressed data.

    Raises:
        SnappyDecompressionError: If the stream is malformed or corrupted.

    Handled chunk types:
      - 0x00 (compressed): Decompress and verify CRC.
      - 0x01 (uncompressed): Verify CRC, copy directly.
      - 0xff (stream identifier): Validate and skip.
      - 0x02-0x7f (reserved unskippable): Raise error.
      - 0x80-0xfe (reserved skippable): Skip silently.
    """
    # Step 1: Validate minimum length.
    #
    # A valid stream must have at least the stream identifier (10 bytes).
    if len(data) < len(STREAM_IDENTIFIER):
        raise SnappyDecompressionError("Input too short for framed snappy")

    # Step 2: Validate stream identifier.
    #
    # The first 10 bytes MUST be the magic sequence.
    if not data.startswith(STREAM_IDENTIFIER):
        raise SnappyDecompressionError("Invalid stream identifier")

    # Step 3: Process chunks.
    #
    # We iterate through the stream, processing each chunk according to its type.
    # Output is accumulated in a bytearray for efficiency.
    output = bytearray()
    pos = len(STREAM_IDENTIFIER)

    while pos < len(data):
        # Read chunk header: [type: 1][length: 3 LE]

        # Ensure we have a complete header (4 bytes).
        if pos + 4 > len(data):
            raise SnappyDecompressionError("Truncated chunk header")

        # Extract type and length.
        chunk_type = data[pos]
        chunk_length = int.from_bytes(data[pos + 1 : pos + 4], "little")
        pos += 4

        # Validate chunk data is present.
        if pos + chunk_length > len(data):
            raise SnappyDecompressionError(
                f"Chunk extends past end: need {chunk_length} bytes at {pos}, "
                f"have {len(data) - pos}"
            )

        # Extract chunk data.
        chunk_data = data[pos : pos + chunk_length]
        pos += chunk_length

        # Process based on chunk type

        if chunk_type == CHUNK_TYPE_COMPRESSED:
            # COMPRESSED CHUNK (0x00)
            #
            # Format: [masked_crc: 4 bytes LE][snappy_compressed_payload]
            #
            # The CRC covers the UNCOMPRESSED data.

            # Ensure we have at least the CRC.
            if len(chunk_data) < 4:
                raise SnappyDecompressionError("Compressed chunk too short for CRC")

            # Extract stored CRC and compressed payload.
            stored_crc = int.from_bytes(chunk_data[:4], "little")
            compressed_payload = chunk_data[4:]

            # Decompress using raw Snappy.
            uncompressed = raw_decompress(compressed_payload)

            # Enforce maximum chunk size (spec section 4.2).
            #
            # A malicious encoder could claim a huge decompressed size.
            # We reject chunks exceeding 64 KiB to bound memory usage.
            if len(uncompressed) > MAX_UNCOMPRESSED_CHUNK_SIZE:
                raise SnappyDecompressionError(
                    f"Decompressed chunk exceeds {MAX_UNCOMPRESSED_CHUNK_SIZE} bytes"
                )

            # Verify CRC matches uncompressed data.
            computed_crc = _mask_crc(_crc32c(uncompressed))
            if stored_crc != computed_crc:
                raise SnappyDecompressionError(
                    f"CRC mismatch: stored {stored_crc:#x}, computed {computed_crc:#x}"
                )

            # Append to output.
            output.extend(uncompressed)

        elif chunk_type == CHUNK_TYPE_UNCOMPRESSED:
            # UNCOMPRESSED CHUNK (0x01)
            #
            # Format: [masked_crc: 4 bytes LE][raw_payload]
            #
            # Used when compression would expand the data.

            # Ensure we have at least the CRC.
            if len(chunk_data) < 4:
                raise SnappyDecompressionError("Uncompressed chunk too short for CRC")

            # Extract stored CRC and raw payload.
            stored_crc = int.from_bytes(chunk_data[:4], "little")
            raw_payload = chunk_data[4:]

            # Enforce maximum chunk size (spec section 4.3).
            if len(raw_payload) > MAX_UNCOMPRESSED_CHUNK_SIZE:
                raise SnappyDecompressionError(
                    f"Uncompressed chunk exceeds {MAX_UNCOMPRESSED_CHUNK_SIZE} bytes"
                )

            # Verify CRC matches the raw payload.
            computed_crc = _mask_crc(_crc32c(raw_payload))
            if stored_crc != computed_crc:
                raise SnappyDecompressionError(
                    f"CRC mismatch: stored {stored_crc:#x}, computed {computed_crc:#x}"
                )

            # Append to output.
            output.extend(raw_payload)

        elif chunk_type == 0xFF:
            # STREAM IDENTIFIER CHUNK (0xff)
            #
            # Can appear multiple times (e.g., concatenated streams).
            # Spec section 4.1: Verify length is 6 and content is "sNaPpY".

            if chunk_length != 6:
                raise SnappyDecompressionError(
                    f"Stream identifier chunk must be 6 bytes, got {chunk_length}"
                )
            if chunk_data != b"sNaPpY":
                raise SnappyDecompressionError("Invalid stream identifier content")

            # Valid identifier - nothing to output, just continue.

        elif 0x02 <= chunk_type <= 0x7F:
            # RESERVED UNSKIPPABLE CHUNK (0x02-0x7f)
            #
            # Spec section 4.5: These are reserved for future use.
            # A decoder MUST NOT silently skip them; it must error.
            raise SnappyDecompressionError(f"Unknown unskippable chunk type: {chunk_type:#x}")

        else:
            # RESERVED SKIPPABLE CHUNK (0x80-0xfe) or PADDING (0xfe)
            #
            # Spec sections 4.4, 4.6: These are reserved for future use.
            # A decoder MUST skip them silently and continue processing.
            pass

    return bytes(output)
