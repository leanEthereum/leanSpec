"""
libp2p transport layer for leanSpec.

This module provides the low-level networking primitives required for
peer-to-peer communication in the Lean Ethereum consensus protocol.

Architecture:
    QUIC Transport (TLS 1.3 encryption + native multiplexing)
        -> multistream-select 1.0 per stream (application protocol)
    Application Protocol (gossipsub, reqresp)

Components:
    - quic/: QUIC transport with libp2p-tls authentication
    - multistream/: Protocol negotiation
    - connection/: Connection abstractions (re-exports QUIC types)
    - identity/: secp256k1 keypairs and identity proofs

QUIC provides encryption and multiplexing natively, eliminating the need
for separate Noise and yamux layers that TCP would require. This results
in fewer round-trips and simpler connection establishment.

References:
    - ethereum/consensus-specs p2p-interface.md
    - libp2p/specs quic, tls, multistream-select
"""

from .connection import Connection, ConnectionManager, Stream
from .identity import (
    NOISE_IDENTITY_PREFIX,
    IdentityKeypair,
    create_identity_proof,
    verify_identity_proof,
    verify_signature,
)
from .multistream import (
    MULTISTREAM_PROTOCOL_ID,
    NegotiationError,
    negotiate_client,
    negotiate_server,
)
from .peer_id import Base58, KeyType, Multihash, MultihashCode, PeerId, PublicKeyProto
from .protocols import StreamReaderProtocol, StreamWriterProtocol
from .quic import QuicConnection, QuicConnectionManager, generate_libp2p_certificate

__all__ = [
    # Connection management
    "Connection",
    "Stream",
    "ConnectionManager",
    # QUIC transport
    "QuicConnection",
    "QuicConnectionManager",
    "generate_libp2p_certificate",
    # Identity (secp256k1 keypair)
    "IdentityKeypair",
    "verify_signature",
    "NOISE_IDENTITY_PREFIX",
    "create_identity_proof",
    "verify_identity_proof",
    # multistream-select
    "MULTISTREAM_PROTOCOL_ID",
    "NegotiationError",
    "negotiate_client",
    "negotiate_server",
    # PeerId (peer_id module)
    "PeerId",
    "PublicKeyProto",
    "Multihash",
    "KeyType",
    "MultihashCode",
    "Base58",
    # Stream protocols
    "StreamReaderProtocol",
    "StreamWriterProtocol",
]
