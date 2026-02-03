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
    MessageDecodingError,
    MessageEncodingError,
    decode_message,
    encode_message,
    generate_request_id,
)
from .config import DiscoveryConfig
from .crypto import (
    AES_KEY_SIZE,
    COMPRESSED_PUBKEY_SIZE,
    CTR_IV_SIZE,
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    ID_SIGNATURE_SIZE,
    UNCOMPRESSED_PUBKEY_SIZE,
    aes_ctr_decrypt,
    aes_ctr_encrypt,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    ecdh_agree,
    generate_secp256k1_keypair,
    pubkey_to_compressed,
    pubkey_to_uncompressed,
    sign_id_nonce,
    verify_id_nonce_signature,
)
from .handshake import (
    HandshakeError,
    HandshakeManager,
    HandshakeResult,
    HandshakeState,
    PendingHandshake,
)
from .keys import (
    DISCV5_KEY_AGREEMENT_INFO,
    SESSION_KEY_SIZE,
    compute_node_id,
    derive_keys,
    derive_keys_from_pubkey,
)
from .messages import (
    MAX_REQUEST_ID_LENGTH,
    PROTOCOL_ID,
    PROTOCOL_VERSION,
    Distance,
    FindNode,
    IdNonce,
    IPv4,
    IPv6,
    MessageType,
    Nodes,
    Nonce,
    PacketFlag,
    Ping,
    Pong,
    Port,
    RequestId,
    StaticHeader,
    TalkReq,
    TalkResp,
    WhoAreYouAuthdata,
)
from .packet import (
    HANDSHAKE_HEADER_SIZE,
    MESSAGE_AUTHDATA_SIZE,
    STATIC_HEADER_SIZE,
    WHOAREYOU_AUTHDATA_SIZE,
    HandshakeAuthdata,
    MessageAuthdata,
    PacketHeader,
    PacketType,
    decode_handshake_authdata,
    decode_message_authdata,
    decode_packet_header,
    decode_whoareyou_authdata,
    decrypt_message,
    encode_handshake_authdata,
    encode_message_authdata,
    encode_packet,
    encode_whoareyou_authdata,
    generate_id_nonce,
    generate_nonce,
)
from .packet import (
    WhoAreYouAuthdata as WhoAreYouAuthdataDecoded,
)
from .routing import KBucket, NodeEntry, RoutingTable, log2_distance, xor_distance
from .service import DiscoveryService, LookupResult
from .session import BondCache, Session, SessionCache
from .transport import DiscoveryTransport

__all__ = [
    # Config
    "DiscoveryConfig",
    # Messages
    "MAX_REQUEST_ID_LENGTH",
    "PROTOCOL_ID",
    "PROTOCOL_VERSION",
    "Distance",
    "IdNonce",
    "IPv4",
    "IPv6",
    "Nonce",
    "Port",
    "RequestId",
    "MessageType",
    "PacketFlag",
    "FindNode",
    "Nodes",
    "Ping",
    "Pong",
    "TalkReq",
    "TalkResp",
    "StaticHeader",
    "WhoAreYouAuthdata",
    # Routing
    "KBucket",
    "NodeEntry",
    "RoutingTable",
    "log2_distance",
    "xor_distance",
    # Crypto
    "AES_KEY_SIZE",
    "COMPRESSED_PUBKEY_SIZE",
    "CTR_IV_SIZE",
    "GCM_NONCE_SIZE",
    "GCM_TAG_SIZE",
    "ID_SIGNATURE_SIZE",
    "UNCOMPRESSED_PUBKEY_SIZE",
    "aes_ctr_encrypt",
    "aes_ctr_decrypt",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "ecdh_agree",
    "generate_secp256k1_keypair",
    "pubkey_to_compressed",
    "pubkey_to_uncompressed",
    "sign_id_nonce",
    "verify_id_nonce_signature",
    # Keys
    "DISCV5_KEY_AGREEMENT_INFO",
    "SESSION_KEY_SIZE",
    "compute_node_id",
    "derive_keys",
    "derive_keys_from_pubkey",
    # Codec
    "DiscoveryMessage",
    "MessageDecodingError",
    "MessageEncodingError",
    "encode_message",
    "decode_message",
    "generate_request_id",
    # Packet
    "STATIC_HEADER_SIZE",
    "MESSAGE_AUTHDATA_SIZE",
    "WHOAREYOU_AUTHDATA_SIZE",
    "HANDSHAKE_HEADER_SIZE",
    "PacketType",
    "PacketHeader",
    "MessageAuthdata",
    "WhoAreYouAuthdataDecoded",
    "HandshakeAuthdata",
    "encode_packet",
    "decode_packet_header",
    "encode_message_authdata",
    "decode_message_authdata",
    "encode_whoareyou_authdata",
    "decode_whoareyou_authdata",
    "encode_handshake_authdata",
    "decode_handshake_authdata",
    "decrypt_message",
    "generate_nonce",
    "generate_id_nonce",
    # Session
    "Session",
    "SessionCache",
    "BondCache",
    # Handshake
    "HandshakeState",
    "PendingHandshake",
    "HandshakeResult",
    "HandshakeError",
    "HandshakeManager",
    # Transport
    "DiscoveryTransport",
    # Service
    "DiscoveryService",
    "LookupResult",
]
