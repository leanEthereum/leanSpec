"""Networking Configuration Constants."""

from typing import Final

from lean_spec.types.byte_arrays import Bytes1

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

MESSAGE_DOMAIN_INVALID_SNAPPY: Final[DomainType] = Bytes1(b"\x00")
"""1-byte domain for gossip message-id isolation of invalid snappy messages.

Per Ethereum spec, prepended to the message hash when decompression fails.
"""

MESSAGE_DOMAIN_VALID_SNAPPY: Final[DomainType] = Bytes1(b"\x01")
"""1-byte domain for gossip message-id isolation of valid snappy messages.

Per Ethereum spec, prepended to the message hash when decompression succeeds.
"""

# --- Gossipsub Protocol IDs ---

GOSSIPSUB_PROTOCOL_ID_V10: Final[str] = "/meshsub/1.0.0"
"""Gossipsub v1.0 protocol ID - basic mesh pubsub."""

GOSSIPSUB_PROTOCOL_ID_V11: Final[str] = "/meshsub/1.1.0"
"""Gossipsub v1.1 protocol ID - peer scoring, extended validators.

This is the minimum version required by the Ethereum consensus spec.
"""

GOSSIPSUB_PROTOCOL_ID_V12: Final[str] = "/meshsub/1.2.0"
"""Gossipsub v1.2 protocol ID - IDONTWANT bandwidth optimization."""

GOSSIPSUB_DEFAULT_PROTOCOL_ID: Final[str] = GOSSIPSUB_PROTOCOL_ID_V11
"""
Default protocol ID per Ethereum consensus spec requirements.

The Ethereum consensus P2P spec states:
"Clients MUST support the gossipsub v1 libp2p Protocol including the gossipsub v1.1 extension."
"""

# --- Gossipsub Parameters ---

PRUNE_BACKOFF: Final[int] = 60
"""Default PRUNE backoff duration in seconds.

When a peer is pruned from the mesh, they must wait this duration
before attempting to re-graft. This prevents rapid mesh churn.
"""

MESSAGE_ID_SIZE: Final[int] = 20
"""Size of gossipsub message IDs in bytes.

Per Ethereum spec, message IDs are the first 20 bytes of SHA256(domain + topic_len + topic + data).
"""

MAX_ERROR_MESSAGE_SIZE: Final[int] = 256
"""Maximum error message size in bytes per Ethereum P2P spec (ErrorMessage: List[byte, 256])."""
