"""
Bincode-compatible serialization helpers for XMSS.

This module implements the specific VarInt (Variable Integer) encoding used by
Rust's `bincode` crate with `bincode::config::standard()`.

See: https://docs.rs/bincode/latest/bincode/config/index.html
"""

from typing import Callable, List, Tuple, TypeVar

T = TypeVar("T")
"""Generic type variable for vector items"""

# Bincode VarInt markers (little-endian)
#
# Values < 251 are stored directly as a single byte.
MARKER_U16 = 251
"""0xfb: followed by 2 bytes"""
MARKER_U32 = 252
"""0xfc: followed by 4 bytes"""
MARKER_U64 = 253
"""0xfd: followed by 8 bytes"""


def encode_varint_u64(value: int) -> bytes:
    """
    Encode an unsigned 64-bit integer into Bincode's VarInt format.

    Bincode compresses integers to save space:
    - 0..250     -> 1 byte  (the value itself)
    - 251..2^16  -> 3 bytes (0xfb + u16)
    - 2^16..2^32 -> 5 bytes (0xfc + u32)
    - 2^32..2^64 -> 9 bytes (0xfd + u64)

    Args:
        value: The integer to encode (0 <= value < 2^64).

    Returns:
        Varint-encoded bytes.

    Raises:
        ValueError: If value is negative or too large.
    """
    # Sanity checks for valid u64 range
    if value < 0:
        raise ValueError(f"Cannot encode negative value as varint: {value}")
    if value >= (1 << 64):
        raise ValueError(f"Value too large for u64 varint: {value}")

    # Case 1: Fits in a single byte
    if value < MARKER_U16:
        return value.to_bytes(1, "little")

    # Case 2: Fits in u16
    #
    # Prefix 0xfb, then write value as 2 bytes little-endian.
    if value < (1 << 16):
        return b"\xfb" + value.to_bytes(2, "little")

    # Case 3: Fits in u32
    #
    # Prefix 0xfc, then write value as 4 bytes little-endian.
    if value < (1 << 32):
        return b"\xfc" + value.to_bytes(4, "little")

    # Case 4: Fits in u64 (everything else)
    #
    # Prefix 0xfd, then write value as 8 bytes little-endian.
    return b"\xfd" + value.to_bytes(8, "little")


def decode_varint_u64(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Decode a Bincode VarInt from a byte buffer.

    Args:
        data: The raw bytes.
        offset: Where to start reading.

    Returns:
        (decoded_value, bytes_consumed)

    Raises:
        ValueError: If data is too short or marker is invalid.
    """
    # Ensure we have at least one byte to read the marker/value
    if offset >= len(data):
        raise ValueError("Not enough data to decode varint")

    # Read the first byte (the marker or the immediate value)
    marker = data[offset]

    # Case 1: The byte IS the value (0-250)
    if marker < MARKER_U16:
        return marker, 1

    # Process Markers
    #
    # We check for the specific marker byte, ensure enough data exists for the payload,
    # and then decode the Little Endian integer.

    if marker == MARKER_U16:  # 0xfb
        if offset + 3 > len(data):
            raise ValueError("Not enough data for u16 varint")
        value = int.from_bytes(data[offset + 1 : offset + 3], "little")
        return value, 3

    elif marker == MARKER_U32:  # 0xfc
        if offset + 5 > len(data):
            raise ValueError("Not enough data for u32 varint")
        value = int.from_bytes(data[offset + 1 : offset + 5], "little")
        return value, 5

    elif marker == MARKER_U64:  # 0xfd
        if offset + 9 > len(data):
            raise ValueError("Not enough data for u64 varint")
        value = int.from_bytes(data[offset + 1 : offset + 9], "little")
        return value, 9

    else:
        # Markers 254/255 are reserved/unused in standard bincode
        raise ValueError(f"Invalid varint marker: {marker}")


def serialize_vec(items: List[T], item_serializer: Callable[[T], bytes]) -> bytes:
    """
    Serialize a list into a Bincode vector (Vec<T>).

    Format: [Len (VarInt)] || [Item 0] || [Item 1] ... || [Item N]

    Args:
        items: List of objects to serialize.
        item_serializer: Function converting T -> bytes.

    Returns:
        Bincode-formatted bytes.
    """
    # Encode the number of items (Vec length) as a VarInt prefix
    length_bytes = encode_varint_u64(len(items))

    # Serialize every item in order and concatenate them
    #
    # We use a generator expression inside join for memory efficiency
    payload_bytes = b"".join(item_serializer(item) for item in items)

    # Combine length prefix and payload
    return length_bytes + payload_bytes


def deserialize_vec(
    data: bytes,
    offset: int,
    item_deserializer: Callable[[bytes, int], Tuple[T, int]],
) -> Tuple[List[T], int]:
    """
    Deserialize a Bincode vector (Vec<T>).

    Args:
        data: Raw byte source.
        offset: Start index.
        item_deserializer: Function(data, offset) -> (item, bytes_read).

    Returns:
        (list_of_items, total_bytes_consumed)
    """
    # Read the vector length (how many items follow)
    count, consumed = decode_varint_u64(data, offset)
    current_offset = offset + consumed

    items = []

    # Loop strictly `count` times to read items
    for _ in range(count):
        # Deserialize one item at the current position
        item, item_bytes = item_deserializer(data, current_offset)

        items.append(item)

        # Advance the cursor
        current_offset += item_bytes

    # Calculate total bytes read (start to current cursor)
    total_consumed = current_offset - offset

    return items, total_consumed
