"""Packing helpers for SSZ Merkleization.

These helpers convert existing *serialized* data into 32-byte chunks (Bytes32).
They do not serialize objects themselves; they only arrange bytes into chunks
as required by the SSZ Merkleization rules.

All functions return `list[Bytes32]`, the canonical chunk form fed into `merkleize`.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from lean_spec.subspecs.ssz.constants import BITS_PER_BYTE, BYTES_PER_CHUNK
from lean_spec.types.byte_arrays import Bytes32


def _right_pad_to_chunk(b: bytes) -> bytes:
    """Right-pad `b` with zeros up to a multiple of BYTES_PER_CHUNK.

    SSZ Merkleization packs serialized basic values into 32-byte "chunks".
    When `b` is not already chunk-aligned, we append zero bytes.
    """
    if len(b) % BYTES_PER_CHUNK == 0:
        return b
    pad = BYTES_PER_CHUNK - (len(b) % BYTES_PER_CHUNK)
    return b + b"\x00" * pad


def _partition_chunks(b: bytes) -> list[Bytes32]:
    """Partition an already-aligned byte-string into 32-byte chunks.

    Precondition: `len(b)` must be a multiple of 32.
    """
    if len(b) == 0:
        return []
    if len(b) % BYTES_PER_CHUNK != 0:
        raise ValueError("partition requires a multiple of BYTES_PER_CHUNK")
    return [Bytes32(b[i : i + BYTES_PER_CHUNK]) for i in range(0, len(b), BYTES_PER_CHUNK)]


def pack_basic_serialized(serialized_basic_values: Iterable[bytes]) -> list[Bytes32]:
    """Pack *serialized* basic values (e.g. uintN/boolean/byte) into chunks.

    Parameters
    ----------
    serialized_basic_values:
        Iterable of bytes objects; each element is already the SSZ-serialized
        form of a basic value.

    Returns:
    -------
    list[Bytes32]
        Concatenated and right-padded chunks ready for Merkleization.
    """
    return _partition_chunks(_right_pad_to_chunk(b"".join(serialized_basic_values)))


def pack_bytes(data: bytes) -> list[Bytes32]:
    """Pack raw bytes (e.g. ByteVector/ByteList content) into 32-byte chunks."""
    return _partition_chunks(_right_pad_to_chunk(data))


def pack_bits(bools: Sequence[bool]) -> list[Bytes32]:
    """Pack a boolean sequence into a bitfield, then into 32-byte chunks.

    Notes:
    -----
    - This does **not** add the Bitlist length-delimiter bit. Callers implementing
      Bitlist should add it separately or mix the list length at the Merkle level.
    - Bit ordering follows SSZ (little-endian within each byte).
    """
    if not bools:
        return []
    byte_len = (len(bools) + (BITS_PER_BYTE - 1)) // BITS_PER_BYTE
    arr = bytearray(byte_len)
    for i, bit in enumerate(bools):
        if bit:
            arr[i // BITS_PER_BYTE] |= 1 << (i % BITS_PER_BYTE)
    return _partition_chunks(_right_pad_to_chunk(bytes(arr)))
