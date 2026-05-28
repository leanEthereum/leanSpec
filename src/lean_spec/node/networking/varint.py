"""
Unsigned LEB128 varint encoding and decoding.

WHAT ARE VARINTS?
-----------------
A varint (variable-length integer) encodes integers using fewer bytes for
smaller values. Unlike fixed-width integers where 300 always takes 4 bytes
(as uint32), varints encode 300 in just 2 bytes.

This matters in network protocols where most values are small:

- Message lengths are typically under 1 KB (1 byte varint)
- Protocol identifiers are small integers (1 byte varint)
- Field numbers in protobuf are usually 1-15 (1 byte varint)


HOW LEB128 ENCODING WORKS
-------------------------
LEB128 (Little-Endian Base 128) splits an integer into 7-bit groups,
encoding each group in one byte. The MSB (bit 7) signals continuation:

- MSB = 1: More bytes follow
- MSB = 0: This is the final byte

The "Little-Endian" name means low-order bits come first.

Byte structure::

    [C|D D D D D D D]
     ^-- Continuation bit (1 = more bytes, 0 = last byte)
       ^-----------^-- 7 bits of data

Size ranges::

    Value 0-127:       1 byte   [0xxxxxxx]
    Value 128-16383:   2 bytes  [1xxxxxxx] [0xxxxxxx]
    Value 16384+:      3+ bytes [1xxxxxxx] [1xxxxxxx] [0xxxxxxx] ...


ENCODING EXAMPLE: VALUE 300
---------------------------
Step 1: Convert to binary
    300 = 0b100101100 (9 bits)

Step 2: Split into 7-bit groups (from right)
    Group 0 (bits 0-6):  0101100 = 44
    Group 1 (bits 7-13): 0000010 = 2

Step 3: Encode each group with continuation bit
    Byte 0: 0101100 + continuation bit = 1|0101100 = 0xAC (172)
    Byte 1: 0000010 + no continuation  = 0|0000010 = 0x02 (2)

Result: [0xAC, 0x02]


DECODING EXAMPLE: BYTES [0xAC, 0x02]
------------------------------------
Step 1: Read first byte (0xAC = 0b10101100)
    Has continuation bit set (MSB = 1)
    Data bits: 0101100 (44)
    Shift: 0, contribution: 44 << 0 = 44

Step 2: Read second byte (0x02 = 0b00000010)
    No continuation bit (MSB = 0) - this is the last byte
    Data bits: 0000010 (2)
    Shift: 7, contribution: 2 << 7 = 256

Step 3: Combine
    44 + 256 = 300


USAGE IN LIBP2P
---------------
Varints appear throughout libp2p protocols:

1. Multistream-select: Message length prefixes
   - Format: [varint length][message + newline]
   - The length includes the trailing newline

2. Protobuf encoding: Field tags and lengths
   - PeerId uses protobuf for public key serialization
   - Wire format: [tag varint][length varint][data]

3. Req/resp framing: Payload size prefixes
   - Enables buffer pre-allocation before decompression
   - Prevents decompression bombs by validating size upfront

4. Noise payloads: Identity binding protobuf fields
   - Encodes identity key and signature lengths


IMPLEMENTATION NOTES
--------------------
This module handles unsigned varints only. Signed varints (ZigZag encoding)
are not needed for libp2p protocols.

Maximum value: 2^64 - 1 (10 bytes)
The 10-byte limit matches protobuf and prevents infinite loops on malformed input.


References:
    LEB128 specification:
        https://en.wikipedia.org/wiki/LEB128
    Protocol Buffers encoding:
        https://protobuf.dev/programming-guides/encoding/#varints
    libp2p specifications:
        https://github.com/libp2p/specs
"""

from __future__ import annotations


class VarintError(Exception):
    """Raised when varint encoding or decoding fails."""


def encode_varint(value: int) -> bytes:
    """
    Encode an unsigned integer as LEB128 varint.

    Splits the integer into 7-bit groups, emitting each as one byte.
    All bytes except the last have the continuation bit (0x80) set.

    Args:
        value: Non-negative integer to encode. Maximum: 2^64 - 1.

    Returns:
        Varint-encoded bytes. Length depends on value:

        - 0-127: 1 byte
        - 128-16383: 2 bytes
        - 16384-2097151: 3 bytes
        - Up to 10 bytes for 64-bit values

    Raises:
        ValueError: If value is negative.
    """
    if value < 0:
        raise ValueError("Varint must be non-negative")

    result = bytearray()

    # Process 7 bits at a time until the value fits in 7 bits.
    #
    # The threshold 0x80 (128) is key: values >= 128 need another byte.
    # For each iteration:
    #   - Extract low 7 bits (value & 0x7F)
    #   - Set continuation bit (| 0x80) to signal more bytes follow
    #   - Shift right by 7 to process next group
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7

    # Emit final byte without continuation bit.
    #
    # At this point, value < 128, so it fits in 7 bits.
    # The missing continuation bit (MSB = 0) signals "end of varint".
    result.append(value)

    return bytes(result)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decode a varint from bytes at the given offset.

    Reads bytes until finding one without the continuation bit set.
    Each byte contributes 7 bits to the result, shifted by its position.

    Args:
        data: Input bytes containing the varint.
        offset: Starting position in data. Defaults to 0.

    Returns:
        Tuple of (decoded_value, bytes_consumed).

        The bytes_consumed count allows callers to advance past
        the varint when parsing a stream of values.

    Raises:
        VarintError: If the input is truncated (runs out of bytes
            before finding the final byte) or exceeds 10 bytes
            (would overflow 64 bits).
    """
    result = 0
    shift = 0
    pos = offset

    while True:
        # Ensure we have more data to read.
        #
        # A varint must end with a byte where MSB = 0.
        # If we run out of data first, the input is truncated.
        if pos >= len(data):
            raise VarintError("Truncated varint")

        byte = data[pos]
        pos += 1

        # Extract 7 data bits and add them at the current position.
        #
        # The shift accumulates: byte 0 contributes bits 0-6,
        # byte 1 contributes bits 7-13, byte 2 contributes bits 14-20, etc.
        result |= (byte & 0x7F) << shift
        shift += 7

        # Check the continuation bit (MSB).
        #
        # If clear (byte & 0x80 == 0), this is the final byte.
        if not (byte & 0x80):
            break

        # Guard against malformed input that never terminates.
        #
        # A 64-bit value needs at most 10 bytes (70 bits, with 6 unused).
        # If we've shifted 70+ bits and still see continuation, the input
        # is invalid or represents a value larger than we can handle.
        if shift >= 70:
            raise VarintError("Varint too long")

    return result, pos - offset
