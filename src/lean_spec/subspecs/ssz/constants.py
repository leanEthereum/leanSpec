"""Constants defined in the SSZ specification."""

BYTES_PER_CHUNK: int = 32
"""The number of bytes in a Merkle tree chunk."""

ZERO_HASH: bytes = b"\x00" * BYTES_PER_CHUNK
"""A zero hash, used for padding in the Merkle tree."""
