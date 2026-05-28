"""
Constants for the Snappy compression algorithm.

Reference: https://github.com/google/snappy
"""

from __future__ import annotations

from typing import Final

#
# Snappy processes data in fixed-size blocks to bound memory usage and
# enable streaming. Each block is compressed independently.

BLOCK_SIZE: Final = 1 << 16
"""Maximum block size in bytes (64 KB).

Large inputs are split into 64 KB blocks, each compressed independently.
This bounds memory usage and enables streaming decompression.
"""

INPUT_MARGIN_BYTES: Final = 15
"""Safety margin at end of input for batch reads.

The compressor reads up to 8 bytes at a time for efficiency. This margin
ensures we don't read past the buffer when near the end.
"""

#
# Each compressed element starts with a tag byte. The lower 2 bits identify
# the element type:
#
#   00 = Literal (uncompressed bytes)
#   01 = Copy with 1-byte offset (max 2047 bytes back)
#   10 = Copy with 2-byte offset (max 65535 bytes back)
#   11 = Copy with 4-byte offset (max 4GB back)

LITERAL: Final = 0b00
"""Tag type for literal (uncompressed) data.

Literals are sequences of bytes copied verbatim from input to output.
Short literals (1-60 bytes) encode the length in the tag byte itself.
Longer literals use 1-4 additional bytes for the length.
"""

COPY_1_BYTE_OFFSET: Final = 0b01
"""Tag type for copy with 1-byte offset.

Compact encoding for short backreferences:
- Length: 4-11 bytes (3 bits in tag)
- Offset: 0-2047 bytes (11 bits: 3 in tag + 8 in next byte)

Total encoding: 2 bytes (tag + offset).
"""

COPY_2_BYTE_OFFSET: Final = 0b10
"""Tag type for copy with 2-byte offset.

Standard encoding for medium backreferences:
- Length: 1-64 bytes (6 bits in tag)
- Offset: 0-65535 bytes (16 bits in next 2 bytes)

Total encoding: 3 bytes (tag + 2 offset bytes).
"""

COPY_4_BYTE_OFFSET: Final = 0b11
"""Tag type for copy with 4-byte offset.

Extended encoding for long backreferences:
- Length: 1-64 bytes (6 bits in tag)
- Offset: 0-4294967295 bytes (32 bits in next 4 bytes)

Total encoding: 5 bytes (tag + 4 offset bytes).
Rarely used since most matches are within 64KB.
"""

#
# The compressor uses a hash table to find matching sequences in previously
# seen data. The hash table maps 4-byte sequences to their positions.

MIN_HASH_TABLE_BITS: Final = 8
"""Minimum hash table size exponent (2^8 = 256 entries)."""

MAX_HASH_TABLE_BITS: Final = 15
"""Maximum hash table size exponent (2^15 = 32768 entries)."""

HASH_MULTIPLIER: Final = 0x1E35A7BD
"""Magic constant for the hash function.

This is a prime-like constant that spreads input bits well across
the hash output. The formula is: hash = (input * HASH_MULTIPLIER) >> shift
"""

#
# Literal lengths are encoded differently based on size:
#
#   1-60 bytes:   Length stored in upper 6 bits of tag byte.
#   61+ bytes:    Tag byte indicates extra length bytes follow.

MAX_INLINE_LITERAL_LENGTH: Final = 60
"""Maximum literal length that fits in the tag byte.

For lengths 1-60, we encode (length - 1) in the upper 6 bits of the tag.
For lengths > 60, we use additional bytes to encode the length.
"""

LITERAL_LENGTH_1_BYTE: Final = 60
"""Tag marker indicating 1 additional byte for literal length.

The actual length is stored as a single byte following the tag.
Supports literals up to 256 bytes.
"""

LITERAL_LENGTH_2_BYTES: Final = 61
"""Tag marker indicating 2 additional bytes for literal length.

The actual length is stored as little-endian uint16 following the tag.
Supports literals up to 65536 bytes.
"""

LITERAL_LENGTH_3_BYTES: Final = 62
"""Tag marker indicating 3 additional bytes for literal length.

The actual length is stored as little-endian uint24 following the tag.
Supports literals up to 16777216 bytes.
"""

LITERAL_LENGTH_4_BYTES: Final = 63
"""Tag marker indicating 4 additional bytes for literal length.

The actual length is stored as little-endian uint32 following the tag.
Supports literals up to 4294967296 bytes.
"""

MAX_COPY_1_LENGTH: Final = 11
"""Maximum copy length for 1-byte offset encoding (4-11 bytes)."""

MIN_COPY_1_LENGTH: Final = 4
"""Minimum copy length for 1-byte offset encoding."""

MAX_COPY_1_OFFSET: Final = 2047
"""Maximum offset for 1-byte offset encoding (11 bits)."""

MAX_COPY_2_OFFSET: Final = 65535
"""Maximum offset for 2-byte offset encoding (16 bits)."""

#
# The uncompressed length is encoded as a varint at the start of the
# compressed data. Varints use 7 bits per byte, with the high bit
# indicating continuation.

VARINT_CONTINUATION_BIT: Final = 0x80
"""High bit set in varint bytes to indicate more bytes follow."""

VARINT_DATA_MASK: Final = 0x7F
"""Mask to extract the 7 data bits from a varint byte."""
