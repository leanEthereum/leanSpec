"""Constants used by SSZ merkleization."""

from __future__ import annotations

from typing import Final

BYTES_PER_CHUNK: Final = 32
"""Width of a Merkle leaf chunk in bytes."""

BITS_PER_CHUNK: Final = BYTES_PER_CHUNK * 8
"""Width of a Merkle leaf chunk in bits."""
