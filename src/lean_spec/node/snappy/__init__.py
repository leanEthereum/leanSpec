"""
Pure Python Snappy compression library.

Snappy is a fast compression/decompression algorithm developed by Google.
It prioritizes speed over compression ratio, making it ideal for real-time
applications and network protocols.

The implementation follows the Snappy format specification:
https://github.com/google/snappy/blob/main/format_description.txt
"""

from __future__ import annotations

from lean_spec.node.snappy.compress import compress, max_compressed_length
from lean_spec.node.snappy.decompress import SnappyDecompressionError, decompress
from lean_spec.node.snappy.framing import frame_compress, frame_decompress

__all__ = [
    # Core API (raw block format)
    "compress",
    "decompress",
    # Framing API (streaming format used by Ethereum)
    "frame_compress",
    "frame_decompress",
    # Utilities
    "max_compressed_length",
    # Exceptions
    "SnappyDecompressionError",
]
