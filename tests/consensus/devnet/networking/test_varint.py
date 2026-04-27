"""Test vectors for LEB128 varint encoding."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


# --- Single-byte values (0-127) ---


def test_varint_zero(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint zero encodes as a single 0x00 byte."""
    networking_codec(codec_name="varint", input={"value": 0})


def test_varint_one(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint one encodes as 0x01."""
    networking_codec(codec_name="varint", input={"value": 1})


def test_varint_max_one_byte(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 127 is the largest value fitting in a single byte."""
    networking_codec(codec_name="varint", input={"value": 127})


# --- Two-byte values (128-16383) ---


def test_varint_min_two_bytes(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 128 is the smallest value requiring two bytes."""
    networking_codec(codec_name="varint", input={"value": 128})


def test_varint_150(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 150. Classic protobuf documentation example."""
    networking_codec(codec_name="varint", input={"value": 150})


def test_varint_255(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 255. Max Uint8 boundary."""
    networking_codec(codec_name="varint", input={"value": 255})


def test_varint_256(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 256. First value past Uint8 range."""
    networking_codec(codec_name="varint", input={"value": 256})


def test_varint_300(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 300. The example from the module docstring."""
    networking_codec(codec_name="varint", input={"value": 300})


def test_varint_max_two_bytes(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 16383 is the largest value fitting in two bytes."""
    networking_codec(codec_name="varint", input={"value": 16383})


# --- Multi-byte boundaries ---


def test_varint_min_three_bytes(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 16384 is the smallest value requiring three bytes."""
    networking_codec(codec_name="varint", input={"value": 16384})


def test_varint_max_three_bytes(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 2097151 is the largest value fitting in three bytes."""
    networking_codec(codec_name="varint", input={"value": 2097151})


def test_varint_max_four_bytes(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 268435455 is the largest value fitting in four bytes."""
    networking_codec(codec_name="varint", input={"value": 268435455})


# --- Large values ---


def test_varint_uint32_max(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 2^32 - 1. Maximum 32-bit unsigned integer."""
    networking_codec(codec_name="varint", input={"value": 2**32 - 1})


def test_varint_uint64_max(networking_codec: NetworkingCodecTestFiller) -> None:
    """Varint 2^64 - 1. Maximum 64-bit value, requires 10 bytes."""
    networking_codec(codec_name="varint", input={"value": 2**64 - 1})
