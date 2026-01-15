"""Unit tests for SSZ packing helpers."""

from __future__ import annotations

from typing import List as PyList

import pytest

from lean_spec.subspecs.ssz.constants import BITS_PER_BYTE, BYTES_PER_CHUNK
from lean_spec.subspecs.ssz.pack import (
    _partition_chunks,
    _right_pad_to_chunk,
    pack_basic_serialized,
    pack_bits,
    pack_bytes,
)
from lean_spec.types.byte_arrays import Bytes32


def _hex_chunks(chunks: PyList[Bytes32]) -> PyList[str]:
    """Return a list of hex strings for Bytes32 chunks."""
    # Bytes32 is bytes-like
    return [bytes(c).hex() for c in chunks]


def _pad32_hex(payload_hex: str) -> str:
    """Right-pad hex to 32 bytes (64 hex chars)."""
    return (payload_hex + ("00" * 32))[:64]


def test_right_pad_to_chunk_empty() -> None:
    assert _right_pad_to_chunk(b"") == b""


def test_right_pad_to_chunk_already_aligned() -> None:
    data = bytes(range(32))
    out = _right_pad_to_chunk(data)
    assert out == data  # unchanged


def test_right_pad_to_chunk_partial() -> None:
    data = b"\x01\x02\x03"  # 3 bytes
    out = _right_pad_to_chunk(data)
    assert len(out) % BYTES_PER_CHUNK == 0
    assert out.startswith(data)
    assert out[len(data) :] == b"\x00" * (BYTES_PER_CHUNK - len(data))


def test_partition_chunks_empty() -> None:
    assert _partition_chunks(b"") == []


def test_partition_chunks_exact_one() -> None:
    data = bytes(range(32))
    chunks = _partition_chunks(data)
    assert len(chunks) == 1
    assert bytes(chunks[0]) == data


def test_partition_chunks_multiple() -> None:
    data = bytes(range(64))
    chunks = _partition_chunks(data)
    assert len(chunks) == 2
    assert bytes(chunks[0]) == data[:32]
    assert bytes(chunks[1]) == data[32:]


def test_partition_chunks_raises_on_misaligned() -> None:
    with pytest.raises(ValueError):
        _partition_chunks(b"\x00" * 33)


@pytest.mark.parametrize(
    "payload_hex, expected_chunks_hex",
    [
        ("", []),  # no data -> no chunks
        ("01", [_pad32_hex("01")]),
        # A 32-byte payload should become a single 32-byte (64-char hex) chunk.
        ("00" * 32, ["00" * 32]),
        (
            # A 33-byte payload is padded to 64 bytes, becoming two 32-byte chunks.
            "00" * 33,
            ["00" * 32, "00" * 32],
        ),
        (
            "".join(f"{i:02x}" for i in range(40)),  # 40 raw bytes -> 2 chunks
            [
                "".join(f"{i:02x}" for i in range(32)),
                _pad32_hex("".join(f"{i:02x}" for i in range(32, 40))),
            ],
        ),
    ],
)
def test_pack_bytes(payload_hex: str, expected_chunks_hex: PyList[str]) -> None:
    """
    Tests packing of raw bytes into 32-byte chunks for various payload sizes.
    """
    # Pack the input bytes into a list of 32-byte SSZ chunks.
    out = pack_bytes(bytes.fromhex(payload_hex))
    # Compare the hex representation of the output chunks with the expected list.
    assert _hex_chunks(out) == expected_chunks_hex


def test_pack_basic_serialized_empty() -> None:
    assert pack_basic_serialized([]) == []


def test_pack_basic_serialized_small_values() -> None:
    # Two serialized Uint16 (little-endian): 0x4567 -> 67 45, 0x0123 -> 23 01
    values = [b"\x67\x45", b"\x23\x01"]
    out = pack_basic_serialized(values)
    assert len(out) == 1
    assert out[0].hex() == _pad32_hex("67452301")


def test_pack_basic_serialized_multi_chunk() -> None:
    # 40 bytes worth of already-serialized basic scalars (e.g., 40 x uint8)
    values = [bytes([i]) for i in range(40)]
    out = pack_basic_serialized(values)
    assert len(out) == 2
    # first chunk: 0..31
    assert out[0].hex() == "".join(f"{i:02x}" for i in range(32))
    # second chunk: 32..39 then padded
    tail_hex = "".join(f"{i:02x}" for i in range(32, 40))
    assert out[1].hex() == _pad32_hex(tail_hex)


def test_pack_bits_empty() -> None:
    assert pack_bits(()) == []


@pytest.mark.parametrize(
    "bits, expected_first_byte_hex",
    [
        # Matches the mapping used in other tests: first tuple item -> bit 0 (LSB) of first byte.
        ((True, True, False, True, False, True, False, False), "2b"),  # 0b00101011
        ((False, True, False, True), "0a"),  # 0b00001010
        ((False, True, False), "02"),  # 0b00000010
    ],
)
def test_pack_bits_small(bits: tuple[bool, ...], expected_first_byte_hex: str) -> None:
    chunks = pack_bits(bits)
    # Always at least one chunk if there are bits.
    assert len(chunks) == 1
    first = bytes(chunks[0])
    assert first[0] == int(expected_first_byte_hex, 16)
    # Remaining of the first chunk must be zero-padded
    assert first[1:] == b"\x00" * (BYTES_PER_CHUNK - 1)


def test_pack_bits_two_full_chunks_all_ones_512() -> None:
    # 512 bits -> 64 bytes -> exactly 2 chunks of 0xff
    bits = (True,) * 512
    chunks = pack_bits(bits)
    assert len(chunks) == 2
    assert bytes(chunks[0]) == b"\xff" * 32
    assert bytes(chunks[1]) == b"\xff" * 32


def test_pack_bits_cross_chunk_boundary_257_ones() -> None:
    # 257 ones -> 33 bytes: 32 bytes of 0xff, then 0x01, then pad to 32
    bits = (True,) * 257
    chunks = pack_bits(bits)
    assert len(chunks) == 2
    assert bytes(chunks[0]) == b"\xff" * 32
    second = bytes(chunks[1])
    assert second[0] == 0x01
    assert second[1:] == b"\x00" * 31


def test_pack_bits_byte_len_rounding() -> None:
    # Verify byte length rounding: len= (n + 7)//8
    n = 9
    bits = tuple(True if i < n else False for i in range(n))
    chunks = pack_bits(bits)
    # 9 bits -> 2 bytes -> still 1 chunk after padding
    assert len(chunks) == 1
    first = bytes(chunks[0])
    # first two bytes should be: 0xff and 0x01 (lower bit set); rest zeros
    assert first[:2] == b"\xff\x01"
    assert first[2:] == b"\x00" * 30


def test_pack_bits_bit_ordering_examples() -> None:
    # Spot-check the little-endian-in-byte policy.
    # Set only bit 7 (MSB) of the first byte: tuple index 7 -> value 1
    bits = tuple(True if i == 7 else False for i in range(8))
    chunks = pack_bits(bits)
    assert len(chunks) == 1
    assert bytes(chunks[0])[0] == 0x80  # MSB set
    # Set only bit 0 (LSB) of the second byte: index 8
    bits = tuple(True if i == 8 else False for i in range(16))
    chunks = pack_bits(bits)
    assert len(chunks) == 1
    assert bytes(chunks[0])[0] == 0x00
    assert bytes(chunks[0])[1] == 0x01
    # Sanity about constants used internally
    assert BITS_PER_BYTE == 8
    assert BYTES_PER_CHUNK == 32
