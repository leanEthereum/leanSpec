"""Pure Python Snappy compression library.

Snappy is a fast compression/decompression algorithm developed by Google.
It prioritizes speed over compression ratio, making it ideal for real-time
applications and network protocols.

Usage::

    from lean_spec.snappy import compress, decompress

    # Compress data before sending
    compressed = compress(data)

    # Decompress received data
    original = decompress(compressed)

The implementation follows the Snappy format specification:
https://github.com/google/snappy/blob/main/format_description.txt
"""

from __future__ import annotations

from .compress import compress, max_compressed_length
from .decompress import (
    SnappyDecompressionError,
    decompress,
    get_uncompressed_length,
    is_valid_compressed_data,
)
from .framing import frame_compress, frame_decompress

__all__ = [
    # Core API (raw block format)
    "compress",
    "decompress",
    # Framing API (streaming format used by Ethereum)
    "frame_compress",
    "frame_decompress",
    # Utilities
    "max_compressed_length",
    "get_uncompressed_length",
    "is_valid_compressed_data",
    # Exceptions
    "SnappyDecompressionError",
]
