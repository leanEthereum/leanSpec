"""
Discovery v5 Protocol Specification

Node Discovery Protocol v5.1 for finding peers in Ethereum networks.

The module provides:
- Wire protocol encoding/decoding
- Cryptographic primitives (AES-CTR/GCM, secp256k1 ECDH)
- Session and handshake management
- UDP transport layer
- High-level discovery service

References:
    - https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md
    - https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md
    - https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md
"""

from .codec import (
    DiscoveryMessage,
    decode_message,
    encode_message,
)
from .config import DiscoveryConfig
from .messages import (
    MAX_REQUEST_ID_LENGTH,
    PROTOCOL_ID,
    PROTOCOL_VERSION,
    Distance,
    FindNode,
    IdNonce,
    MessageType,
    Nodes,
    Nonce,
    Ping,
    Pong,
    RequestId,
    TalkReq,
    TalkResp,
)
from .routing import NodeEntry, RoutingTable
from .service import DiscoveryService, LookupResult

__all__ = [
    # High-level service
    "DiscoveryService",
    "DiscoveryConfig",
    "LookupResult",
    # Message types (for protocol interaction)
    "DiscoveryMessage",
    "encode_message",
    "decode_message",
    # Routing
    "NodeEntry",
    "RoutingTable",
    # Message types (commonly needed)
    "Ping",
    "Pong",
    "FindNode",
    "Nodes",
    "TalkReq",
    "TalkResp",
    # Constants (commonly needed)
    "PROTOCOL_ID",
    "PROTOCOL_VERSION",
    "MAX_REQUEST_ID_LENGTH",
    # Types
    "Distance",
    "IdNonce",
    "Nonce",
    "RequestId",
    "MessageType",
]
