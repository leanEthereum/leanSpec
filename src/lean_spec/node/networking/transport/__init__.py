"""
libp2p transport layer for leanSpec.

This module provides the low-level networking primitives required for
peer-to-peer communication in the Lean Ethereum consensus protocol.

Architecture:
    QUIC Transport (TLS 1.3 encryption + native multiplexing)
        -> multistream-select 1.0 per stream (application protocol)
    Application Protocol (gossipsub, reqresp)

Components:
    - quic/: QUIC transport with libp2p-tls authentication and protocol negotiation
    - identity/: secp256k1 keypairs

QUIC provides encryption and multiplexing natively, eliminating the need
for separate Noise and yamux layers. This results
in fewer round-trips and simpler connection establishment.

References:
    - ethereum/consensus-specs p2p-interface.md
    - libp2p/specs quic, tls, multistream-select
"""

from lean_spec.node.networking.transport.identity import IdentityKeypair, Secp256k1PublicKey
from lean_spec.node.networking.transport.peer_id import (
    Base58,
    KeyType,
    Multihash,
    MultihashCode,
    PeerId,
    PublicKeyProtobuf,
)
from lean_spec.node.networking.transport.quic import (
    NegotiationError,
    QuicConnection,
    QuicConnectionManager,
    generate_libp2p_certificate,
)
from lean_spec.node.networking.transport.quic.stream_adapter import QuicStreamAdapter

__all__ = [
    # QUIC transport
    "QuicConnection",
    "QuicConnectionManager",
    "QuicStreamAdapter",
    "NegotiationError",
    "generate_libp2p_certificate",
    # Identity (secp256k1 keypair)
    "IdentityKeypair",
    "Secp256k1PublicKey",
    # PeerId (peer_id module)
    "PeerId",
    "PublicKeyProtobuf",
    "Multihash",
    "KeyType",
    "MultihashCode",
    "Base58",
]
