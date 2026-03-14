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
    - identity/: secp256k1 keypairs and identity proofs

QUIC provides encryption and multiplexing natively, eliminating the need
for separate Noise and yamux layers. This results
in fewer round-trips and simpler connection establishment.

References:
    - ethereum/consensus-specs p2p-interface.md
    - libp2p/specs quic, tls, multistream-select
"""

from .identity import (
    NOISE_IDENTITY_PREFIX,
    IdentityKeypair,
    Secp256k1PublicKey,
    create_identity_proof,
    verify_identity_proof,
)
from .peer_id import Base58, KeyType, Multihash, MultihashCode, PeerId, PublicKeyProto
from .quic import (
    NegotiationError,
    QuicConnection,
    QuicConnectionManager,
    generate_libp2p_certificate,
)
from .quic.stream_adapter import QuicStreamAdapter

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
    "NOISE_IDENTITY_PREFIX",
    "create_identity_proof",
    "verify_identity_proof",
    # PeerId (peer_id module)
    "PeerId",
    "PublicKeyProto",
    "Multihash",
    "KeyType",
    "MultihashCode",
    "Base58",
]
