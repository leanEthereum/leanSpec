"""
Message codec for Discovery v5.

Protocol messages are encoded as::

    message-pt = message-type || message-data
    message-data = RLP([field1, field2, ...])

Message types:
- PING (0x01): [request-id, enr-seq]
- PONG (0x02): [request-id, enr-seq, recipient-ip, recipient-port]
- FINDNODE (0x03): [request-id, [distances...]]
- NODES (0x04): [request-id, total, [ENRs...]]
- TALKREQ (0x05): [request-id, protocol, request]
- TALKRESP (0x06): [request-id, response]

References:
- https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md#protocol-messages
"""

from __future__ import annotations

from lean_spec.subspecs.networking.types import SeqNumber
from lean_spec.types import Uint64, decode_rlp, encode_rlp
from lean_spec.types.rlp import RLPDecodingError
from lean_spec.types.uint import Uint8

from .messages import (
    Distance,
    FindNode,
    MessageType,
    Nodes,
    Ping,
    Pong,
    Port,
    RequestId,
    TalkReq,
    TalkResp,
)

DiscoveryMessage = Ping | Pong | FindNode | Nodes | TalkReq | TalkResp
"""Union of all Discovery v5 protocol messages."""


class MessageEncodingError(Exception):
    """Error encoding a Discovery v5 message."""


class MessageDecodingError(Exception):
    """Error decoding a Discovery v5 message."""


def encode_message(msg: DiscoveryMessage) -> bytes:
    """
    Encode a protocol message to bytes.

    Format: message-type (1 byte) || RLP(message-data)

    Args:
        msg: Protocol message to encode.

    Returns:
        Encoded message bytes.
    """
    if isinstance(msg, Ping):
        return _encode_ping(msg)
    if isinstance(msg, Pong):
        return _encode_pong(msg)
    if isinstance(msg, FindNode):
        return _encode_findnode(msg)
    if isinstance(msg, Nodes):
        return _encode_nodes(msg)
    if isinstance(msg, TalkReq):
        return _encode_talkreq(msg)
    if isinstance(msg, TalkResp):
        return _encode_talkresp(msg)
    raise MessageEncodingError(f"Unknown message type: {type(msg).__name__}")


def decode_message(data: bytes) -> DiscoveryMessage:
    """
    Decode a protocol message from bytes.

    Args:
        data: Encoded message bytes.

    Returns:
        Decoded protocol message.

    Raises:
        MessageDecodingError: If message is malformed or unknown type.
    """
    if len(data) < 2:
        raise MessageDecodingError("Message too short")

    msg_type = data[0]
    payload = data[1:]

    try:
        if msg_type == MessageType.PING:
            return _decode_ping(payload)
        if msg_type == MessageType.PONG:
            return _decode_pong(payload)
        if msg_type == MessageType.FINDNODE:
            return _decode_findnode(payload)
        if msg_type == MessageType.NODES:
            return _decode_nodes(payload)
        if msg_type == MessageType.TALKREQ:
            return _decode_talkreq(payload)
        if msg_type == MessageType.TALKRESP:
            return _decode_talkresp(payload)
        raise MessageDecodingError(f"Unknown message type: {msg_type:#x}")
    except RLPDecodingError as e:
        raise MessageDecodingError(f"Invalid RLP: {e}") from e
    except (IndexError, ValueError) as e:
        raise MessageDecodingError(f"Invalid message format: {e}") from e


def _encode_request_id(request_id: RequestId) -> bytes:
    """Encode request ID to minimal bytes."""
    data = bytes(request_id)
    return data.lstrip(b"\x00") or b"\x00"


def _decode_request_id(data: bytes) -> RequestId:
    """Decode request ID from bytes."""
    if len(data) > 8:
        raise ValueError(f"Request ID too long: {len(data)} > 8")
    return RequestId(data=data)


def _encode_uint64(value: Uint64) -> bytes:
    """Encode Uint64 to minimal big-endian bytes."""
    if int(value) == 0:
        return b""
    return int(value).to_bytes((int(value).bit_length() + 7) // 8, "big")


def _decode_uint64(data: bytes) -> Uint64:
    """Decode Uint64 from big-endian bytes."""
    if len(data) == 0:
        return Uint64(0)
    return Uint64(int.from_bytes(data, "big"))


def _encode_ping(msg: Ping) -> bytes:
    """Encode PING message."""
    items = [
        _encode_request_id(msg.request_id),
        _encode_uint64(msg.enr_seq),
    ]
    return bytes([MessageType.PING]) + encode_rlp(items)


def _decode_ping(payload: bytes) -> Ping:
    """Decode PING message."""
    items = decode_rlp(payload)
    if not isinstance(items, list) or len(items) != 2:
        raise MessageDecodingError("PING requires 2 elements")

    return Ping(
        request_id=_decode_request_id(items[0]),
        enr_seq=SeqNumber(_decode_uint64(items[1])),
    )


def _encode_pong(msg: Pong) -> bytes:
    """Encode PONG message."""
    items = [
        _encode_request_id(msg.request_id),
        _encode_uint64(msg.enr_seq),
        msg.recipient_ip,
        int(msg.recipient_port).to_bytes(2, "big") if int(msg.recipient_port) > 0 else b"",
    ]
    return bytes([MessageType.PONG]) + encode_rlp(items)


def _decode_pong(payload: bytes) -> Pong:
    """Decode PONG message."""
    items = decode_rlp(payload)
    if not isinstance(items, list) or len(items) != 4:
        raise MessageDecodingError("PONG requires 4 elements")

    port_bytes = items[3]
    port = int.from_bytes(port_bytes, "big") if port_bytes else 0

    return Pong(
        request_id=_decode_request_id(items[0]),
        enr_seq=SeqNumber(_decode_uint64(items[1])),
        recipient_ip=items[2],
        recipient_port=Port(port),
    )


def _encode_findnode(msg: FindNode) -> bytes:
    """Encode FINDNODE message."""
    distance_items = [_encode_uint64(Uint64(int(d))) for d in msg.distances]
    items = [
        _encode_request_id(msg.request_id),
        distance_items,
    ]
    return bytes([MessageType.FINDNODE]) + encode_rlp(items)


def _decode_findnode(payload: bytes) -> FindNode:
    """Decode FINDNODE message."""
    items = decode_rlp(payload)
    if not isinstance(items, list) or len(items) != 2:
        raise MessageDecodingError("FINDNODE requires 2 elements")

    distances_raw = items[1]
    if not isinstance(distances_raw, list):
        raise MessageDecodingError("FINDNODE distances must be a list")

    distances = [Distance(int.from_bytes(d, "big") if d else 0) for d in distances_raw]

    return FindNode(
        request_id=_decode_request_id(items[0]),
        distances=distances,
    )


def _encode_nodes(msg: Nodes) -> bytes:
    """Encode NODES message."""
    items = [
        _encode_request_id(msg.request_id),
        bytes([int(msg.total)]) if int(msg.total) > 0 else b"",
        msg.enrs,
    ]
    return bytes([MessageType.NODES]) + encode_rlp(items)


def _decode_nodes(payload: bytes) -> Nodes:
    """Decode NODES message."""
    items = decode_rlp(payload)
    if not isinstance(items, list) or len(items) != 3:
        raise MessageDecodingError("NODES requires 3 elements")

    total_bytes = items[1]
    total = total_bytes[0] if total_bytes else 0

    enrs_raw = items[2]
    if not isinstance(enrs_raw, list):
        raise MessageDecodingError("NODES enrs must be a list")

    enrs = [e if isinstance(e, bytes) else b"" for e in enrs_raw]

    return Nodes(
        request_id=_decode_request_id(items[0]),
        total=Uint8(total),
        enrs=enrs,
    )


def _encode_talkreq(msg: TalkReq) -> bytes:
    """Encode TALKREQ message."""
    items = [
        _encode_request_id(msg.request_id),
        msg.protocol,
        msg.request,
    ]
    return bytes([MessageType.TALKREQ]) + encode_rlp(items)


def _decode_talkreq(payload: bytes) -> TalkReq:
    """Decode TALKREQ message."""
    items = decode_rlp(payload)
    if not isinstance(items, list) or len(items) != 3:
        raise MessageDecodingError("TALKREQ requires 3 elements")

    return TalkReq(
        request_id=_decode_request_id(items[0]),
        protocol=items[1],
        request=items[2],
    )


def _encode_talkresp(msg: TalkResp) -> bytes:
    """Encode TALKRESP message."""
    items = [
        _encode_request_id(msg.request_id),
        msg.response,
    ]
    return bytes([MessageType.TALKRESP]) + encode_rlp(items)


def _decode_talkresp(payload: bytes) -> TalkResp:
    """Decode TALKRESP message."""
    items = decode_rlp(payload)
    if not isinstance(items, list) or len(items) != 2:
        raise MessageDecodingError("TALKRESP requires 2 elements")

    return TalkResp(
        request_id=_decode_request_id(items[0]),
        response=items[1],
    )


def generate_request_id() -> RequestId:
    """Generate a random request ID."""
    import os

    return RequestId(data=os.urandom(8))
