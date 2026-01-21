"""Constants defined in the SSZ specification."""

BYTES_PER_CHUNK: int = 32
"""Number of bytes per Merkle chunk."""

BITS_PER_BYTE: int = 8
"""Number of bits per byte."""

BITS_PER_CHUNK: int = BYTES_PER_CHUNK * BITS_PER_BYTE
"""Number of bits per Merkle chunk (256 bits)."""
