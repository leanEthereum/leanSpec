"""
libp2p transport layer for leanSpec.

This module provides the low-level networking primitives required for
peer-to-peer communication in the Lean Ethereum consensus protocol.

Architecture:
    TCP Socket (asyncio)
        -> multistream-select 1.0 (negotiate /noise)
    Noise Session (XX handshake)
        -> multistream-select 1.0 (negotiate /yamux/1.0.0)
    yamux Multiplexed Streams (with per-stream flow control)
        -> multistream-select 1.0 per stream (application protocol)
    Application Protocol (gossipsub, reqresp)

Components:
    - noise/: Noise_XX_25519_ChaChaPoly_SHA256 encryption
    - yamux/: Stream multiplexing with flow control (256KB window per stream)
    - multistream/: Protocol negotiation
    - connection/: Connection lifecycle management

Why yamux? mplex is deprecated in libp2p due to lack of flow control,
causing head-of-line blocking. yamux provides per-stream windows (256KB)
and WINDOW_UPDATE frames for backpressure.

References:
    - ethereum/consensus-specs p2p-interface.md
    - libp2p/specs noise, yamux, multistream-select
    - hashicorp/yamux spec.md
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
from .noise import CipherState, NoiseHandshake, NoiseSession
from .peer_id import Base58, KeyType, Multihash, MultihashCode, PeerId, PublicKeyProto
from .protocols import StreamReaderProtocol, StreamWriterProtocol
from .yamux import (
    YamuxError,
    YamuxFlags,
    YamuxFrame,
    YamuxGoAwayCode,
    YamuxSession,
    YamuxStream,
    YamuxType,
)

__all__ = [
    # Connection management
    "Connection",
    "Stream",
    "ConnectionManager",
    # Identity (secp256k1 keypair)
    "IdentityKeypair",
    "verify_signature",
    "NOISE_IDENTITY_PREFIX",
    "create_identity_proof",
    "verify_identity_proof",
    # Noise protocol
    "NoiseHandshake",
    "NoiseSession",
    "CipherState",
    # yamux multiplexer
    "YamuxSession",
    "YamuxStream",
    "YamuxFrame",
    "YamuxType",
    "YamuxFlags",
    "YamuxGoAwayCode",
    "YamuxError",
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
