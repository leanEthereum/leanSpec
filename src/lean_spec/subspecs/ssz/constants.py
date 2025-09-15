"""Constants defined in the SSZ specification."""

from lean_spec.types.byte_arrays import Bytes32

BYTES_PER_CHUNK: int = 32
"""Number of bytes per Merkle chunk."""

BITS_PER_BYTE: int = 8
"""Number of bits per byte."""

ZERO_HASH: Bytes32 = Bytes32(b"\x00" * BYTES_PER_CHUNK)
"""A zero hash, used for padding in Merkleization."""
