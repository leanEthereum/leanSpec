"""
Req/Resp wire format codec for Ethereum consensus networking.

This module implements the wire format for Ethereum's request/response protocol,
used for peer-to-peer communication between consensus clients.


WHY THIS FORMAT?
----------------
Ethereum's req/resp protocol runs over libp2p streams. The wire format must:

  1. STREAM-FRIENDLY: Work with libp2p's stream-based I/O (no message framing).
  2. SIZE-EFFICIENT: Minimize bandwidth for large payloads (blocks, attestations).
  3. INTEROPERABLE: Match other clients.

The format achieves this by:
  - Using varints for compact length encoding (1 byte for values < 128).
  - Applying Snappy framing for compression with error detection.
  - Prefixing with uncompressed length for buffer allocation.


WIRE FORMATS
------------
Request format::

    [varint: uncompressed_length][snappy_framed_ssz_payload]

Response format::

    [response_code: 1 byte][varint: uncompressed_length][snappy_framed_ssz_payload]

The response code indicates success (0) or various error conditions (1-3).


VARINT ENCODING (LEB128)
------------------------
Varints use unsigned LEB128 (Little-Endian Base 128), the same encoding as
Protocol Buffers. Each byte encodes 7 bits of data with bit 7 as continuation::

    Value 0-127:     1 byte   [0xxxxxxx]
    Value 128-16383: 2 bytes  [1xxxxxxx] [0xxxxxxx]
    Value 16384+:    3+ bytes [1xxxxxxx] [1xxxxxxx] [0xxxxxxx] ...

The MSB (bit 7) indicates whether more bytes follow:
  - 0: This is the last byte.
  - 1: More bytes follow.

Example: 300 = 0b100101100
  - Split into 7-bit groups: 0b10 (high), 0b0101100 (low)
  - Encode low group with continuation: 0b10101100 = 0xAC
  - Encode high group (final): 0b00000010 = 0x02
  - Result: [0xAC, 0x02]


LENGTH PREFIX
-------------
The varint length prefix serves two purposes:

  1. BUFFER ALLOCATION: Receiver knows the uncompressed size upfront.
  2. VALIDATION: After decompression, verify the size matches.

This prevents decompression bombs (small compressed → huge uncompressed).


References:
    Ethereum P2P spec:
        https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md
    LEB128 encoding:
        https://en.wikipedia.org/wiki/LEB128
    Snappy framing:
        https://github.com/google/snappy/blob/master/framing_format.txt
"""

from __future__ import annotations

from enum import IntEnum

from lean_spec.snappy import SnappyDecompressionError, frame_compress, frame_decompress

from ..config import MAX_PAYLOAD_SIZE
from ..varint import VarintError, decode_varint, encode_varint


class CodecError(Exception):
    """Raised when encoding or decoding fails.

    This covers all wire format errors:
      - Truncated or malformed varints
      - Payload size limit violations
      - Snappy decompression failures
      - Length mismatches after decompression
    """


def encode_request(ssz_data: bytes) -> bytes:
    """
    Encode an SSZ-serialized request for transmission.

    Args:
        ssz_data: SSZ-encoded request message.

    Returns:
        Wire-format bytes ready for transmission.

    Raises:
        CodecError: If the payload exceeds MAX_PAYLOAD_SIZE (10 MiB).

    Wire format::

        [varint: uncompressed_length][snappy_framed_payload]

    Why this order?
        The length comes first so receivers can:
        1. Reject oversized requests before decompressing.
        2. Allocate the correct buffer size upfront.
    """
    # Step 1: Validate payload size.
    #
    # Reject requests that exceed the protocol limit.
    # This prevents encoding payloads that peers will reject.
    if len(ssz_data) > MAX_PAYLOAD_SIZE:
        raise CodecError(f"Payload too large: {len(ssz_data)} > {MAX_PAYLOAD_SIZE}")

    # Step 2: Compress with Snappy framing.
    #
    # Snappy framing adds:
    #   - Stream identifier (10 bytes)
    #   - CRC32C checksums for error detection
    #   - Chunking for large payloads
    compressed = frame_compress(ssz_data)

    # Step 3: Prepend uncompressed length as varint.
    #
    # The length is of the ORIGINAL data, not the compressed data.
    # This lets receivers validate after decompression.
    length_prefix = encode_varint(len(ssz_data))

    return length_prefix + compressed


def decode_request(data: bytes) -> bytes:
    """
    Decode a wire-format request to SSZ bytes.

    Args:
        data: Wire-format request bytes.

    Returns:
        SSZ-encoded request message.

    Raises:
        CodecError: If the request is malformed, corrupted, or oversized.

    Validation steps:
        1. Decode varint length prefix.
        2. Reject if declared length exceeds MAX_PAYLOAD_SIZE.
        3. Decompress Snappy framed payload.
        4. Verify decompressed size matches declared length.
    """
    # Step 1: Reject empty input.
    if not data:
        raise CodecError("Empty request")

    # Step 2: Decode the varint length prefix.
    #
    # This tells us the expected uncompressed size.
    try:
        declared_length, varint_size = decode_varint(data)
    except VarintError as e:
        raise CodecError(f"Invalid request length: {e}") from e

    # Step 3: Validate declared length.
    #
    # Reject before decompressing to prevent resource exhaustion.
    if declared_length > MAX_PAYLOAD_SIZE:
        raise CodecError(f"Declared length too large: {declared_length} > {MAX_PAYLOAD_SIZE}")

    # Step 4: Decompress Snappy framed payload.
    #
    # The payload starts after the varint prefix.
    compressed_data = data[varint_size:]
    try:
        decompressed = frame_decompress(compressed_data)
    except SnappyDecompressionError as e:
        raise CodecError(f"Decompression failed: {e}") from e

    # Step 5: Validate length matches.
    #
    # This catches corrupted data or malicious length claims.
    if len(decompressed) != declared_length:
        raise CodecError(f"Length mismatch: declared {declared_length}, got {len(decompressed)}")

    return decompressed


class ResponseCode(IntEnum):
    """
    Response codes for req/resp protocol messages.

    The first byte of every response indicates success or failure:
      - On success (code 0), the payload contains the requested data.
      - On failure (codes 1-3), the payload contains an error message.

    Wire format::

        [response_code: 1 byte][varint_length][snappy_framed_payload]

    Unknown codes are handled gracefully:
      - Codes 4-127: Treated as SERVER_ERROR (reserved for future use).
      - Codes 128-255: Treated as INVALID_REQUEST (invalid range).

    Reference:
        https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md
    """

    SUCCESS = 0
    """Request completed successfully. Payload contains the response data."""

    INVALID_REQUEST = 1
    """Request was malformed or violated protocol rules."""

    SERVER_ERROR = 2
    """Server encountered an internal error processing the request."""

    RESOURCE_UNAVAILABLE = 3
    """Requested resource (block, blob, etc.) is not available."""

    def encode(self, ssz_data: bytes) -> bytes:
        """
        Encode an SSZ-serialized response for transmission.

        Args:
            ssz_data: SSZ-encoded response message, or UTF-8 error for failures.

        Returns:
            Wire-format bytes ready for transmission.

        Raises:
            CodecError: If the payload exceeds MAX_PAYLOAD_SIZE (10 MiB).

        Wire format::

            [response_code: 1 byte][varint: uncompressed_length][snappy_framed_payload]
        """
        # Step 1: Validate payload size.
        if len(ssz_data) > MAX_PAYLOAD_SIZE:
            raise CodecError(f"Payload too large: {len(ssz_data)} > {MAX_PAYLOAD_SIZE}")

        # Step 2: Compress with Snappy framing.
        compressed = frame_compress(ssz_data)

        # Step 3: Build response: [code][length][payload].
        #
        # The code byte comes first so receivers can quickly determine
        # whether to expect data or an error message.
        output = bytearray()

        # Response code (1 byte).
        output.append(self)

        # Uncompressed length as varint.
        output.extend(encode_varint(len(ssz_data)))

        # Snappy framed payload.
        output.extend(compressed)

        return bytes(output)

    @classmethod
    def decode(cls, data: bytes) -> tuple[ResponseCode, bytes]:
        """
        Decode a wire-format response.

        Args:
            data: Wire-format response bytes.

        Returns:
            Tuple of (response_code, ssz_data).

        Raises:
            CodecError: If the response is malformed, corrupted, or oversized.
        """
        # Step 1: Reject empty input.
        if not data:
            raise CodecError("Empty response")

        # Step 2: Ensure minimum length.
        #
        # Need at least: 1 byte (code) + 1 byte (minimum varint).
        if len(data) < 2:
            raise CodecError("Response too short")

        # Step 3: Extract and interpret response code.
        #
        # The first byte is the response code.
        raw_code = data[0]
        try:
            code = cls(raw_code)
        except ValueError:
            # Handle unknown codes gracefully.
            #
            # - Codes 4-127: Reserved, treat as server error.
            # - Codes 128-255: Invalid range, treat as invalid request.
            if raw_code <= 127:
                code = cls.SERVER_ERROR
            else:
                code = cls.INVALID_REQUEST

        # Step 4: Decode the varint length prefix.
        #
        # Starts at offset 1 (after the code byte).
        try:
            declared_length, varint_size = decode_varint(data, offset=1)
        except VarintError as e:
            raise CodecError(f"Invalid response length: {e}") from e

        # Step 5: Validate declared length.
        if declared_length > MAX_PAYLOAD_SIZE:
            raise CodecError(f"Declared length too large: {declared_length} > {MAX_PAYLOAD_SIZE}")

        # Step 6: Decompress Snappy framed payload.
        #
        # Payload starts after code (1 byte) + varint.
        compressed_data = data[1 + varint_size :]
        try:
            decompressed = frame_decompress(compressed_data)
        except SnappyDecompressionError as e:
            raise CodecError(f"Decompression failed: {e}") from e

        # Step 7: Validate length matches.
        if len(decompressed) != declared_length:
            raise CodecError(
                f"Length mismatch: declared {declared_length}, got {len(decompressed)}"
            )

        return code, decompressed
