"""Networking Types"""

from enum import IntEnum, auto

from lean_spec.types import Uint64
from lean_spec.types.byte_arrays import Bytes4, Bytes32

DomainType = Bytes4
"""4-byte domain for message-id isolation in Gossipsub."""

NodeId = Bytes32
"""32-byte node identifier for Discovery v5, derived from ``keccak256(pubkey)``."""

ForkDigest = Bytes4
"""4-byte fork identifier ensuring network isolation between forks."""

SeqNumber = Uint64
"""Sequence number used in ENR records, metadata, and ping messages."""

SubnetId = Uint64
"""Subnet identifier (0-63) for attestation subnet partitioning."""

ProtocolId = str
"""Libp2p protocol identifier, e.g. ``/eth2/beacon_chain/req/status/1/ssz_snappy``."""

Multiaddr = str
"""Multiaddress string, e.g. ``/ip4/192.168.1.1/tcp/9000``."""


class ConnectionState(IntEnum):
    """
    Peer connection state machine.

    Tracks the lifecycle of a connection to a peer::

        DISCONNECTED -> CONNECTING -> CONNECTED -> DISCONNECTING -> DISCONNECTED

    These states map directly to libp2p connection events.
    """

    DISCONNECTED = auto()
    """No active connection to this peer."""

    CONNECTING = auto()
    """TCP/QUIC connection in progress."""

    CONNECTED = auto()
    """Transport established, can exchange protocol messages."""

    DISCONNECTING = auto()
    """Graceful shutdown in progress (Goodbye sent/received)."""


class GoodbyeReason(IntEnum):
    """
    Reason codes for the Goodbye request/response message.

    Sent when gracefully disconnecting from a peer to indicate why
    the connection is being closed.

    **Official codes (from spec):**

    +------+---------------------+
    | Code | Meaning             |
    +======+=====================+
    | 1    | Client shutdown     |
    +------+---------------------+
    | 2    | Irrelevant network  |
    +------+---------------------+
    | 3    | Fault/error         |
    +------+---------------------+

    References:
    -----------
    - Goodbye spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#goodbye-v1
    """

    CLIENT_SHUTDOWN = 1
    """Node is shutting down normally."""

    IRRELEVANT_NETWORK = 2
    """Peer is on a different fork or network."""

    FAULT_OR_ERROR = 3
    """Generic error detected in peer communication."""
