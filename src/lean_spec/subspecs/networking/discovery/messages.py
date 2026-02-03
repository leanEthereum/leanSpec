"""
Discovery v5 Protocol Messages

Wire protocol messages for Node Discovery Protocol v5.1.

Packet Structure:
    packet = masking-iv || masked-header || message

Message Encoding:
    message-pt   = message-type || message-data
    message-data = [request-id, ...]  (RLP encoded)

References:
    - https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md
"""

from __future__ import annotations

from enum import IntEnum
from typing import ClassVar

from lean_spec.subspecs.networking.types import SeqNumber
from lean_spec.types import StrictBaseModel
from lean_spec.types.byte_arrays import BaseByteList, BaseBytes
from lean_spec.types.uint import Uint8, Uint16

PROTOCOL_ID: bytes = b"discv5"
"""Protocol identifier in packet header. 6 bytes."""

PROTOCOL_VERSION: int = 0x0001
"""Current protocol version (v5.1)."""

MAX_REQUEST_ID_LENGTH: int = 8
"""Maximum length of request-id in bytes."""


class RequestId(BaseByteList):
    """
    Request identifier for matching requests with responses.

    Variable length up to 8 bytes. Assigned by the requester and echoed
    in responses. Selection of values is implementation-defined.
    """

    LIMIT: ClassVar[int] = MAX_REQUEST_ID_LENGTH


class IPv4(BaseBytes):
    """IPv4 address as 4 bytes."""

    LENGTH: ClassVar[int] = 4


class IPv6(BaseBytes):
    """IPv6 address as 16 bytes."""

    LENGTH: ClassVar[int] = 16


class IdNonce(BaseBytes):
    """
    Identity nonce for WHOAREYOU packets.

    128-bit random value used in the identity verification procedure.
    """

    LENGTH: ClassVar[int] = 16


class Nonce(BaseBytes):
    """
    Message nonce for packet encryption.

    96-bit value. Must be unique for every message packet.
    """

    LENGTH: ClassVar[int] = 12


Distance = Uint16
"""Log2 distance (0-256). Distance 0 returns the node's own ENR."""

Port = Uint16
"""UDP port number (0-65535)."""


class PacketFlag(IntEnum):
    """
    Packet type identifier in the protocol header.

    Determines the encoding of the authdata section.
    """

    MESSAGE = 0
    """Ordinary message packet. authdata = src-id (32 bytes)."""

    WHOAREYOU = 1
    """Challenge packet. authdata = id-nonce || enr-seq (24 bytes)."""

    HANDSHAKE = 2
    """Handshake message packet. authdata = variable size."""


# =============================================================================
# Message Type Identifiers
# =============================================================================


class MessageType(IntEnum):
    """
    Message type identifiers in the encrypted message payload.

    Encoded as the first byte of message-pt before RLP message-data.
    """

    PING = 0x01
    """Liveness check. message-data = [request-id, enr-seq]."""

    PONG = 0x02
    """Response to PING. message-data = [request-id, enr-seq, ip, port]."""

    FINDNODE = 0x03
    """Query nodes. message-data = [request-id, [distances...]]."""

    NODES = 0x04
    """Response with ENRs. message-data = [request-id, total, [ENRs...]]."""

    TALKREQ = 0x05
    """App protocol request. message-data = [request-id, protocol, request]."""

    TALKRESP = 0x06
    """App protocol response. message-data = [request-id, response]."""

    # Topic advertisement messages (not finalized in spec)
    REGTOPIC = 0x07
    """Topic registration request (experimental)."""

    TICKET = 0x08
    """Ticket response for topic registration (experimental)."""

    REGCONFIRMATION = 0x09
    """Topic registration confirmation (experimental)."""

    TOPICQUERY = 0x0A
    """Topic query request (experimental)."""


# =============================================================================
# Protocol Messages
# =============================================================================


class Ping(StrictBaseModel):
    """
    PING request (0x01) - Liveness check.

    Verifies a node is online and informs it of the sender's ENR sequence number.
    The recipient compares enr_seq to decide if it needs the sender's latest record.

    Wire format:
        message-data = [request-id, enr-seq]
    """

    request_id: RequestId
    """Unique identifier for request/response matching."""

    enr_seq: SeqNumber
    """Sender's ENR sequence number."""


class Pong(StrictBaseModel):
    """
    PONG response (0x02) - Reply to PING.

    Confirms liveness and reports the sender's observed external endpoint.
    Used for NAT detection and ENR endpoint verification.

    Wire format:
        message-data = [request-id, enr-seq, recipient-ip, recipient-port]
    """

    request_id: RequestId
    """Echoed from the PING request."""

    enr_seq: SeqNumber
    """Responder's ENR sequence number."""

    recipient_ip: bytes
    """Sender's IP as seen by responder. 4 bytes (IPv4) or 16 bytes (IPv6)."""

    recipient_port: Port
    """Sender's UDP port as seen by responder."""


class FindNode(StrictBaseModel):
    """
    FINDNODE request (0x03) - Query nodes at distances.

    Requests nodes from the recipient's routing table at specified log2 distances.
    The recommended result limit is 16 nodes per query.

    Wire format:
        message-data = [request-id, [distance₁, distance₂, ...]]

    Distance semantics:
        - Distance 0: Returns the recipient's own ENR
        - Distance 1-256: Returns nodes at that log2 distance from recipient
    """

    request_id: RequestId
    """Unique identifier for request/response matching."""

    distances: list[Distance]
    """Log2 distances to query. Each value in range 0-256."""


class Nodes(StrictBaseModel):
    """
    NODES response (0x04) - ENR records from routing table.

    Response to FINDNODE or TOPICQUERY. May be split across multiple messages
    to stay within the 1280 byte UDP packet limit.

    Wire format:
        message-data = [request-id, total, [ENR₁, ENR₂, ...]]

    Recipients should verify returned nodes match the requested distances.
    """

    request_id: RequestId
    """Echoed from the FINDNODE request."""

    total: Uint8
    """Total NODES messages for this request. Enables reassembly."""

    enrs: list[bytes]
    """RLP-encoded ENR records. Max 300 bytes each per EIP-778."""


class TalkReq(StrictBaseModel):
    """
    TALKREQ request (0x05) - Application protocol negotiation.

    Enables higher-layer protocols to communicate through Discovery v5.
    Used by Ethereum for subnet discovery (eth2) and Portal Network.

    Wire format:
        message-data = [request-id, protocol, request]

    The recipient must respond with TALKRESP. If the protocol is unknown,
    the response must contain empty data.
    """

    request_id: RequestId
    """Unique identifier for request/response matching."""

    protocol: bytes
    """Protocol identifier (e.g., b"eth2", b"portal")."""

    request: bytes
    """Protocol-specific request payload."""


class TalkResp(StrictBaseModel):
    """
    TALKRESP response (0x06) - Reply to TALKREQ.

    Empty response indicates the protocol is unknown to the recipient.

    Wire format:
        message-data = [request-id, response]
    """

    request_id: RequestId
    """Echoed from the TALKREQ request."""

    response: bytes
    """Protocol-specific response. Empty if protocol unknown."""


class StaticHeader(StrictBaseModel):
    """
    Fixed-size portion of the packet header.

    Total size: 23 bytes (6 + 2 + 1 + 12 + 2).

    The header is masked using AES-CTR with masking-key = dest-id[:16].
    """

    protocol_id: bytes = PROTOCOL_ID
    """Protocol identifier. Must be b"discv5" (6 bytes)."""

    version: Uint16 = Uint16(PROTOCOL_VERSION)
    """Protocol version. Currently 0x0001."""

    flag: Uint8
    """Packet type: 0=message, 1=whoareyou, 2=handshake."""

    nonce: Nonce
    """96-bit message nonce. Must be unique per packet."""

    authdata_size: Uint16
    """Byte length of the authdata section following this header."""


class WhoAreYouAuthdata(StrictBaseModel):
    """
    Authdata for WHOAREYOU packets (flag=1).

    Sent when the recipient cannot decrypt an incoming message packet.
    The nonce in the packet header is set to the nonce of the failed message.

    Total size: 24 bytes (16 + 8).
    """

    id_nonce: IdNonce
    """128-bit random value for identity verification."""

    enr_seq: SeqNumber
    """Recipient's known ENR sequence for the sender. 0 if unknown."""
