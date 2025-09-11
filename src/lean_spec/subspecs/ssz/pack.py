"""Packing helpers for SSZ Merkleization.

These helpers convert existing *serialized* data into 32-byte chunks (Bytes32).
They do not serialize objects themselves; they only arrange bytes into chunks
as required by the SSZ Merkleization rules.

Design notes
------------
- We keep these helpers in a dedicated class (`Packer`) to make call sites explicit
  and discoverable (e.g., `Packer.pack_bytes(...)`), while remaining purely static.
- All functions return `list[Bytes32]`, the canonical chunk form fed into `merkleize`.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence

from lean_spec.subspecs.ssz.constants import BITS_PER_BYTE, BYTES_PER_CHUNK
from lean_spec.types.byte_arrays import Bytes32


class Packer:
    """Collection of static helpers to pack byte data into 32-byte chunks."""

    @staticmethod
    def _right_pad_to_chunk(b: bytes) -> bytes:
        """Right-pad `b` with zeros up to a multiple of BYTES_PER_CHUNK.

        SSZ Merkleization packs serialized basic values into 32-byte "chunks".
        When `b` is not already chunk-aligned, we append zero bytes.
        """
        # Already aligned? Return as-is.
        if len(b) % BYTES_PER_CHUNK == 0:
            return b
        # Compute the minimal pad size to reach the next multiple of 32.
        pad = BYTES_PER_CHUNK - (len(b) % BYTES_PER_CHUNK)
        return b + b"\x00" * pad

    @staticmethod
    def _partition_chunks(b: bytes) -> List[Bytes32]:
        """Partition an already-aligned byte-string into 32-byte chunks.

        Precondition: `len(b)` must be a multiple of 32.
        """
        if len(b) == 0:
            return []
        if len(b) % BYTES_PER_CHUNK != 0:
            raise ValueError("partition requires a multiple of BYTES_PER_CHUNK")
        # Slice in steps of 32 to build Bytes32 chunks.
        return [Bytes32(b[i : i + BYTES_PER_CHUNK]) for i in range(0, len(b), BYTES_PER_CHUNK)]

    @staticmethod
    def pack_basic_serialized(serialized_basic_values: Iterable[bytes]) -> List[Bytes32]:
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
        # Concatenate the serialized representations of individual basic values.
        joined = b"".join(serialized_basic_values)
        # Right-pad, then partition into 32-byte slices.
        return Packer._partition_chunks(Packer._right_pad_to_chunk(joined))

    @staticmethod
    def pack_bytes(data: bytes) -> List[Bytes32]:
        """Pack raw bytes (e.g. ByteVector/ByteList content) into 32-byte chunks."""
        return Packer._partition_chunks(Packer._right_pad_to_chunk(data))

    @staticmethod
    def pack_bits(bools: Sequence[bool]) -> List[Bytes32]:
        """Pack a boolean sequence into a bitfield, then into 32-byte chunks.

        Notes:
        -----
        - This does **not** add the Bitlist length-delimiter bit. Callers implementing
          Bitlist should add it separately or mix the list length at the Merkle level.
        - Bit ordering follows SSZ (little-endian within each byte).
        """
        if not bools:
            return []
        # Pack 8 bools per byte (round up).
        byte_len = (len(bools) + (BITS_PER_BYTE - 1)) // BITS_PER_BYTE
        arr = bytearray(byte_len)
        for i, bit in enumerate(bools):
            if bit:
                # Set the (i % 8)-th bit of the (i // 8)-th byte.
                arr[i // BITS_PER_BYTE] |= 1 << (i % BITS_PER_BYTE)
        return Packer._partition_chunks(Packer._right_pad_to_chunk(bytes(arr)))
