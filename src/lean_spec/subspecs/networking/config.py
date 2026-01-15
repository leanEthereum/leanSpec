"""Networking Configuration Constants."""

from typing_extensions import Final

from lean_spec.types.byte_arrays import Bytes4

from .types import DomainType

# --- Request/Response Limits ---

MAX_REQUEST_BLOCKS: Final[int] = 2**10
"""Maximum number of blocks in a single request (1024)."""

MAX_PAYLOAD_SIZE: Final[int] = 10 * 1024 * 1024
"""Maximum uncompressed payload size in bytes (10 MiB)."""

# --- Timeouts (in seconds) ---

TTFB_TIMEOUT: Final[float] = 5.0
"""Time-to-first-byte timeout.

Maximum time to wait for the first byte of a response after sending a request.
If no data arrives within this window, the request is considered failed.
"""

RESP_TIMEOUT: Final[float] = 10.0
"""Response timeout.

Maximum total time to receive a complete response. This covers the entire
response, including all chunks for multi-part responses like BlocksByRange.
"""

# --- Gossip Message Domains ---

MESSAGE_DOMAIN_INVALID_SNAPPY: Final[DomainType] = Bytes4(b"\x00\x00\x00\x00")
"""4-byte domain for gossip message-id isolation of invalid snappy messages."""

MESSAGE_DOMAIN_VALID_SNAPPY: Final[DomainType] = Bytes4(b"\x01\x00\x00\x00")
"""4-byte domain for gossip message-id isolation of valid snappy messages."""
