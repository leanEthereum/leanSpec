"""
Snappy decompression implementation.

This module implements the decompression (decoding) side of the Snappy codec.


WHAT IS DECOMPRESSION?
----------------------
Decompression reverses compression: it takes a compressed stream and
reconstructs the original data.

The compressed stream contains:
  1. A length prefix (how big the output will be).
  2. A sequence of operations (literals and copies).

Decompression simply executes these operations in order.


HOW DECOMPRESSION WORKS
-----------------------
The decompressor reads the stream and executes two types of operations:

  LITERAL: "Here are N raw bytes, copy them to output."
      Input:  [tag] [N bytes of data]
      Action: Append the N bytes directly to output.

  COPY: "Go back X bytes in the output, copy Y bytes."
      Input:  [tag] [offset bytes]
      Action: Read from earlier output, append to output.


Example:
-------
Compressed: [length=8] [literal "ABCD"] [copy offset=4, length=4]

Step 1: Read length = 8. Output will be 8 bytes.

Step 2: Execute literal "ABCD".
    Output: "ABCD"

Step 3: Execute copy (offset=4, length=4).
    Go back 4 bytes -> position 0 ("A").
    Copy 4 bytes: "ABCD".
    Output: "ABCDABCD"

Step 4: Output is 8 bytes. Done!

Result: "ABCDABCD"


OVERLAPPING COPIES
------------------
An important subtlety: copies can overlap with themselves.

If offset < length, we copy bytes that we're currently writing.
This enables efficient run-length encoding (RLE).

Example: To produce "AAAA":
  - Literal "A"        -> Output: "A"
  - Copy offset=1, length=3:
      Copy output[-1] = 'A' -> Output: "AA"
      Copy output[-1] = 'A' -> Output: "AAA"
      Copy output[-1] = 'A' -> Output: "AAAA"

The copy keeps reading the same position as the output grows,
producing repeated characters efficiently.


Reference: https://github.com/google/snappy/blob/main/format_description.txt
"""

from __future__ import annotations

from .encoding import decode_tag, decode_varint32


class SnappyDecompressionError(Exception):
    """Raised when decompression fails due to malformed data."""


def decompress(data: bytes) -> bytes:
    """Decompress Snappy-compressed data.

    Args:
        data: Snappy-compressed bytes.

    Returns:
        Original uncompressed data.

    Raises:
        SnappyDecompressionError: If the data is malformed or corrupt.
    """
    if not data:
        raise SnappyDecompressionError("Empty input")

    # Step 1: Read the uncompressed length.
    #
    # The first bytes are a varint encoding the final output size.
    # This lets us validate the output and (optionally) pre-allocate memory.
    #
    # Example: data = [0x08, ...] -> length = 8
    try:
        uncompressed_length, varint_bytes = decode_varint32(data, 0)
    except ValueError as e:
        raise SnappyDecompressionError(f"Invalid length varint: {e}") from e

    # Length = 0 is valid: the original data was empty.
    if uncompressed_length == 0:
        return b""

    # Step 2: Initialize output buffer.
    #
    # We build the output incrementally.
    # Copy operations need to read from earlier positions, so we can't
    # just write to a pre-allocated buffer at arbitrary positions.
    output = bytearray()
    pos = varint_bytes  # Current read position in input

    # Step 3: Process tags until output is complete.
    #
    # Each iteration:
    #   1. Read and decode a tag.
    #   2. Execute the operation (literal or copy).
    #   3. Advance the input position.
    while len(output) < uncompressed_length:
        # Check for truncated input.
        if pos >= len(data):
            raise SnappyDecompressionError(
                f"Unexpected end of input at position {pos}, "
                f"output has {len(output)} bytes but expected {uncompressed_length}"
            )

        # Decode the tag.
        #
        # Returns:
        #   tag_type: "literal" or "copy"
        #   length: number of bytes to copy/emit
        #   copy_offset: for copies, how far back to look (0 for literals)
        #   tag_bytes: how many bytes the tag consumed
        try:
            tag_type, length, copy_offset, tag_bytes = decode_tag(data, pos)
        except ValueError as e:
            raise SnappyDecompressionError(f"Invalid tag at position {pos}: {e}") from e

        pos += tag_bytes

        if tag_type == "literal":
            # LITERAL: Copy raw bytes from input to output.
            #
            # The next `length` bytes in the input are uncompressed data.
            #
            # Example:
            #   Input at pos: [0x48, 0x65, 0x6c, 0x6c, 0x6f]  ("Hello")
            #   length = 5
            #   -> Append "Hello" to output.
            if pos + length > len(data):
                raise SnappyDecompressionError(
                    f"Literal at position {pos - tag_bytes} extends past end of input: "
                    f"needs {length} bytes but only {len(data) - pos} available"
                )

            output.extend(data[pos : pos + length])
            pos += length

        else:
            # COPY: Duplicate bytes from earlier in the output.
            #
            # Go back `copy_offset` bytes in the output, copy `length` bytes.
            #
            # Example:
            #   Output so far: "ABCD" (4 bytes)
            #   copy_offset = 4, length = 4
            #   -> Go back 4 bytes (to 'A'), copy 4 bytes -> "ABCD"
            #   -> Output becomes "ABCDABCD"
            _execute_copy(output, copy_offset, length, uncompressed_length)

    # Step 4: Verify output length.
    #
    # The output must exactly match the declared length.
    # A mismatch indicates corrupted or malformed data.
    if len(output) != uncompressed_length:
        raise SnappyDecompressionError(
            f"Output length mismatch: got {len(output)}, expected {uncompressed_length}"
        )

    return bytes(output)


def _execute_copy(output: bytearray, offset: int, length: int, max_length: int) -> None:
    """Execute a copy operation, appending bytes to the output buffer.

    Args:
        output: The output buffer (modified in place).
        offset: How many bytes back to start copying from.
        length: How many bytes to copy.
        max_length: Maximum allowed output length.

    Raises:
        SnappyDecompressionError: If the offset is invalid or would overflow.

    The copy reads from `offset` bytes back in the output and appends
    `length` bytes. The source and destination may overlap.

    Example 1: Non-overlapping copy
        output = [A, B, C, D], offset = 4, length = 2

        src_pos = 4 - 4 = 0  (points to 'A')

        Copy 1: append output[0] = 'A' -> [A, B, C, D, A]
        Copy 2: append output[1] = 'B' -> [A, B, C, D, A, B]

        Note: src_pos advances, reading consecutive bytes.

    Example 2: Overlapping copy (run-length encoding)
        output = [A, B, C], offset = 1, length = 4

        src_pos = 3 - 1 = 2  (points to 'C')

        Copy 1: append output[2] = 'C' -> [A, B, C, C], src_pos = 3
        Copy 2: append output[3] = 'C' -> [A, B, C, C, C], src_pos = 4
        Copy 3: append output[4] = 'C' -> [A, B, C, C, C, C], src_pos = 5
        Copy 4: append output[5] = 'C' -> [A, B, C, C, C, C, C], src_pos = 6

        The source keeps advancing into the bytes we just wrote,
        repeating the same character. This is how "CCCCCCCC" is
        encoded as just "C" + copy(offset=1, length=7).
    """
    # Validate offset.
    #
    # offset must be >= 1 (can't copy from "0 bytes back").
    # offset must be <= len(output) (can't read before the buffer).
    if offset < 1:
        raise SnappyDecompressionError(f"Invalid copy offset: {offset}")
    if offset > len(output):
        raise SnappyDecompressionError(
            f"Copy offset {offset} exceeds output buffer size {len(output)}"
        )

    # Check for overflow.
    #
    # The copy must not produce more output than declared.
    if len(output) + length > max_length:
        raise SnappyDecompressionError(
            f"Copy would overflow: {len(output)} + {length} > {max_length}"
        )

    # Calculate source position.
    #
    # "offset bytes back" means: len(output) - offset.
    #
    # Example: output = [A, B, C, D], offset = 2
    #   src_pos = 4 - 2 = 2 (points to 'C')
    src_pos = len(output) - offset

    # Copy byte-by-byte.
    #
    # Why not use slicing like output.extend(output[src_pos:src_pos+length])?
    #
    # Because of overlapping copies! If length > offset, we need to read
    # bytes that we're about to write. Byte-by-byte handles this correctly:
    # each iteration reads from the current output state, which may include
    # bytes written in previous iterations.
    for _ in range(length):
        output.append(output[src_pos])
        src_pos += 1


def get_uncompressed_length(data: bytes) -> int:
    """Read the uncompressed length from compressed data without decompressing.

    Args:
        data: Snappy-compressed bytes.

    Returns:
        The declared uncompressed length.

    Raises:
        SnappyDecompressionError: If the length varint is malformed.

    Useful for:
      - Pre-allocating buffers before decompression.
      - Quick validation of compressed data.
      - Checking if you have enough memory for decompression.
    """
    if not data:
        raise SnappyDecompressionError("Empty input")

    try:
        length, _ = decode_varint32(data, 0)
        return length
    except ValueError as e:
        raise SnappyDecompressionError(f"Invalid length varint: {e}") from e


def is_valid_compressed_data(data: bytes) -> bool:
    """Check if data appears to be valid Snappy-compressed data.

    Args:
        data: Data to check.

    Returns:
        True if the data appears to be valid Snappy format.

    This performs quick validation WITHOUT full decompression:
      1. Checks that the length varint is valid.
      2. Verifies there's data after the varint (unless length is 0).

    Use this for fast rejection of obviously invalid data.

    Note:
        This does NOT guarantee the data will decompress successfully.
        It only checks the header. The compressed content may still
        be corrupted.
    """
    if not data:
        return False

    try:
        length, varint_bytes = decode_varint32(data, 0)

        # Sanity checks:
        #   - If length = 0, data is valid (empty original).
        #   - If length > 0, there must be compressed data after the varint.
        return length == 0 or varint_bytes < len(data)
    except ValueError:
        return False
