"""
Discovery v5 Configuration

Protocol constants and configuration for Node Discovery Protocol v5.1.

References:
    - https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md
"""

from typing import Final

from lean_spec.types import StrictBaseModel

K_BUCKET_SIZE: Final = 16
"""Nodes per k-bucket. Standard Kademlia value balancing table size and lookup efficiency."""

ALPHA: Final = 3
"""Concurrent queries during lookup. Balances speed against network load."""

BUCKET_COUNT: Final = 256
"""Total k-buckets. One per bit of the 256-bit node ID space."""

REQUEST_TIMEOUT_SECS: Final = 0.5
"""Single request timeout. Spec recommends 500ms for request/response."""

HANDSHAKE_TIMEOUT_SECS: Final = 1.0
"""Handshake completion timeout. Spec recommends 1s for full handshake."""

MAX_NODES_RESPONSE: Final = 16
"""Max ENRs per NODES message. Keeps responses under 1280 byte UDP limit."""

BOND_EXPIRY_SECS: Final = 86400
"""Liveness revalidation interval. 24 hours before re-checking a node."""

MAX_PACKET_SIZE: Final = 1280
"""Maximum UDP packet size in bytes."""

MIN_PACKET_SIZE: Final = 63
"""Minimum valid packet size in bytes."""


class DiscoveryConfig(StrictBaseModel):
    """Runtime configuration for Discovery v5."""

    k_bucket_size: int = K_BUCKET_SIZE
    """Maximum nodes stored per k-bucket in the routing table."""

    alpha: int = ALPHA
    """Number of concurrent FINDNODE queries during lookup."""

    request_timeout_secs: float = REQUEST_TIMEOUT_SECS
    """Timeout for a single request/response exchange."""

    handshake_timeout_secs: float = HANDSHAKE_TIMEOUT_SECS
    """Timeout for completing the full handshake sequence."""

    max_nodes_response: int = MAX_NODES_RESPONSE
    """Maximum ENR records returned in a single NODES response."""

    bond_expiry_secs: int = BOND_EXPIRY_SECS
    """Seconds before a bonded node requires liveness revalidation."""
