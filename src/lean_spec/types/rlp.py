"""
Recursive Length Prefix (RLP) Encoding
======================================

RLP is Ethereum's serialization format for arbitrary nested binary data.
It is used for encoding transactions, blocks, ENR records, and more.

Encoding Rules
--------------

RLP encodes two types of items:

1. **Byte strings** (including empty string)
2. **Lists** of items (including empty list)

Byte ranges determine the encoding:

+-------------+-----------------------------------------------------------+
| Prefix      | Meaning                                                   |
+=============+===========================================================+
| [0x00-0x7f] | Single byte, value is the byte itself                     |
+-------------+-----------------------------------------------------------+
| [0x80-0xb7] | Short string (0-55 bytes), length = prefix - 0x80         |
+-------------+-----------------------------------------------------------+
| [0xb8-0xbf] | Long string (>55 bytes), prefix - 0xb7 = length of length |
+-------------+-----------------------------------------------------------+
| [0xc0-0xf7] | Short list (0-55 bytes payload), length = prefix - 0xc0   |
+-------------+-----------------------------------------------------------+
| [0xf8-0xff] | Long list (>55 bytes payload), prefix - 0xf7 = len of len |
+-------------+-----------------------------------------------------------+

References:
----------
- Ethereum Yellow Paper, Appendix B
- https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
- https://github.com/ethereum/pyrlp
"""

from __future__ import annotations

from typing import TypeAlias

RLPItem: TypeAlias = bytes | list["RLPItem"]
"""
RLP-encodable item.

Either:
- bytes (a byte string)
- list of RLP items (recursive)
"""


SINGLE_BYTE_MAX = 0x7F
"""Boundary between single-byte encoding [0x00-0x7f] and string prefix."""

SHORT_STRING_PREFIX = 0x80
"""Prefix for short strings (0-55 bytes). Final prefix = 0x80 + length."""

SHORT_STRING_MAX_LEN = 55
"""Maximum string length for short encoding."""

LONG_STRING_BASE = 0xB7
"""Base for long string prefix. Final prefix = 0xb7 + length_of_length."""

SHORT_LIST_PREFIX = 0xC0
"""Prefix for short lists (0-55 bytes payload). Final prefix = 0xc0 + length."""

SHORT_LIST_MAX_LEN = 55
"""Maximum list payload length for short encoding."""

LONG_LIST_BASE = 0xF7
"""Base for long list prefix. Final prefix = 0xf7 + length_of_length."""


def encode_rlp(item: RLPItem) -> bytes:
    """
    Encode an item using RLP.

    Args:
        item: Bytes or nested list of bytes to encode.

    Returns:
        RLP-encoded bytes.

    Raises:
        TypeError: If item is not bytes or list.
    """
    if isinstance(item, bytes):
        return _encode_bytes(item)
    if isinstance(item, list):
        return _encode_list(item)
    raise TypeError(f"Cannot RLP encode type: {type(item).__name__}")


def _encode_bytes(data: bytes) -> bytes:
    """
    Encode a byte string.

    Single bytes in [0x00, 0x7f] encode as themselves.
    Short strings (0-55 bytes) use prefix 0x80 + length.
    Long strings (>55 bytes) use prefix 0xb7 + length-of-length, then length.
    """
    length = len(data)

    # Single byte encoding: values 0x00-0x7f encode as themselves.
    if length == 1 and data[0] <= SINGLE_BYTE_MAX:
        return data

    # Short string: 0-55 bytes.
    if length <= SHORT_STRING_MAX_LEN:
        return bytes([SHORT_STRING_PREFIX + length]) + data

    # Long string: >55 bytes.
    length_bytes = _encode_length(length)
    return bytes([LONG_STRING_BASE + len(length_bytes)]) + length_bytes + data


def _encode_list(items: list[RLPItem]) -> bytes:
    """
    Encode a list of items.

    Recursively encodes each item, concatenates, then adds list prefix.
    Short lists (0-55 bytes payload) use prefix 0xc0 + length.
    Long lists (>55 bytes payload) use prefix 0xf7 + length-of-length, then length.
    """
    # Recursively encode all items.
    payload = b"".join(encode_rlp(item) for item in items)
    length = len(payload)

    # Short list: 0-55 bytes payload.
    if length <= SHORT_LIST_MAX_LEN:
        return bytes([SHORT_LIST_PREFIX + length]) + payload

    # Long list: >55 bytes payload.
    length_bytes = _encode_length(length)
    return bytes([LONG_LIST_BASE + len(length_bytes)]) + length_bytes + payload


def _encode_length(value: int) -> bytes:
    """
    Encode length as minimal big-endian bytes.

    Used for long string/list length encoding where length > 55.
    Returns minimal representation with no leading zeros.
    """
    if value == 0:
        # Defensive: should never be called with 0 for valid long encodings.
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


class RLPDecodingError(Exception):
    """Error during RLP decoding."""


def decode_rlp(data: bytes) -> RLPItem:
    """
    Decode RLP-encoded bytes.

    Args:
        data: RLP-encoded bytes.

    Returns:
        Decoded item (bytes or nested list).

    Raises:
        RLPDecodingError: If data is malformed.
    """
    if len(data) == 0:
        raise RLPDecodingError("Empty RLP data")

    item, consumed = _decode_item(data, 0)

    if consumed != len(data):
        raise RLPDecodingError(f"Trailing data: decoded {consumed} of {len(data)} bytes")

    return item


def decode_rlp_list(data: bytes) -> list[bytes]:
    """
    Decode RLP data as a flat list of byte items.

    This is a convenience function for cases like ENR where
    we expect a flat list of byte strings (no nested lists).

    Args:
        data: RLP-encoded bytes.

    Returns:
        List of decoded byte strings.

    Raises:
        RLPDecodingError: If data is not a list or contains nested lists.
    """
    item = decode_rlp(data)

    if not isinstance(item, list):
        raise RLPDecodingError("Expected RLP list")

    result: list[bytes] = []
    for i, elem in enumerate(item):
        if not isinstance(elem, bytes):
            raise RLPDecodingError(f"Element {i} is not bytes")
        result.append(elem)

    return result


def _decode_item(data: bytes, offset: int) -> tuple[RLPItem, int]:
    """
    Decode a single RLP item starting at offset.

    Returns (decoded_item, bytes_consumed).
    """
    if offset >= len(data):
        raise RLPDecodingError("Unexpected end of data")

    prefix = data[offset]

    # Single byte: 0x00-0x7f.
    if prefix <= SINGLE_BYTE_MAX:
        return data[offset : offset + 1], offset + 1

    # Short string: 0x80-0xb7.
    if prefix <= LONG_STRING_BASE:
        length = prefix - SHORT_STRING_PREFIX
        start = offset + 1
        end = start + length
        _check_bounds(data, end)
        return data[start:end], end

    # Long string: 0xb8-0xbf.
    if prefix < SHORT_LIST_PREFIX:
        len_of_len = prefix - LONG_STRING_BASE
        start = offset + 1
        _check_bounds(data, start + len_of_len)

        # Validate: no leading zeros in length encoding.
        if len_of_len > 1 and data[start] == 0:
            raise RLPDecodingError("Non-canonical: leading zeros in length encoding")

        length = int.from_bytes(data[start : start + len_of_len], "big")

        # Validate: length must require this many bytes.
        if length <= SHORT_STRING_MAX_LEN:
            raise RLPDecodingError("Non-canonical: long string encoding for short string")

        payload_start = start + len_of_len
        payload_end = payload_start + length
        _check_bounds(data, payload_end)
        return data[payload_start:payload_end], payload_end

    # Short list: 0xc0-0xf7.
    if prefix <= LONG_LIST_BASE:
        length = prefix - SHORT_LIST_PREFIX
        start = offset + 1
        end = start + length
        _check_bounds(data, end)
        return _decode_list_payload(data, start, end), end

    # Long list: 0xf8-0xff.
    len_of_len = prefix - LONG_LIST_BASE
    start = offset + 1
    _check_bounds(data, start + len_of_len)

    # Validate: no leading zeros in length encoding.
    if len_of_len > 1 and data[start] == 0:
        raise RLPDecodingError("Non-canonical: leading zeros in length encoding")

    length = int.from_bytes(data[start : start + len_of_len], "big")

    # Validate: length must require this many bytes.
    if length <= SHORT_LIST_MAX_LEN:
        raise RLPDecodingError("Non-canonical: long list encoding for short list")

    payload_start = start + len_of_len
    payload_end = payload_start + length
    _check_bounds(data, payload_end)
    return _decode_list_payload(data, payload_start, payload_end), payload_end


def _decode_list_payload(data: bytes, start: int, end: int) -> list[RLPItem]:
    """Decode list payload between start and end offsets."""
    items: list[RLPItem] = []
    offset = start

    while offset < end:
        item, offset = _decode_item(data, offset)
        items.append(item)

    if offset != end:
        raise RLPDecodingError("List payload length mismatch")

    return items


def _check_bounds(data: bytes, end: int) -> None:
    """Verify end offset is within data bounds."""
    if end > len(data):
        raise RLPDecodingError(f"Data too short: need {end}, have {len(data)}")
