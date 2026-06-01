"""
Gossipsub RPC Protocol Encoding/Decoding
=========================================

This module implements the protobuf wire format for gossipsub RPC messages,
enabling interoperability with rust-libp2p and go-libp2p implementations.

Wire Format
-----------

Gossipsub uses protobuf for RPC encoding. The message structure is::

    message RPC {
        repeated SubOpts subscriptions = 1;
        repeated Message publish = 2;
        optional ControlMessage control = 3;
    }

Each field uses standard protobuf encoding:

- Varint for field tags and lengths
- Length-delimited for strings and nested messages
- Repeated fields appear multiple times with same tag

Why Manual Encoding?
--------------------

We implement protobuf encoding manually rather than using a library because:

1. The schema is fixed and well-known
2. Avoids external dependency for a small surface area
3. Educational value in understanding the wire format
4. Full control over encoding details

References:
-----------
- Protobuf encoding: https://protobuf.dev/programming-guides/encoding/
- go-libp2p-pubsub rpc.protobuf: https://github.com/libp2p/go-libp2p-pubsub/blob/master/pb/rpc.protobuf
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from lean_spec.node.networking.gossipsub.types import TopicId
from lean_spec.node.networking.varint import decode_varint, encode_varint

WIRE_TYPE_VARINT: Final = 0
"""Varint wire type for int32, int64, uint32, uint64, sint32, sint64, bool, enum."""

WIRE_TYPE_64BIT: Final = 1
"""64-bit wire type for fixed64, sfixed64, double."""

WIRE_TYPE_LENGTH_DELIMITED: Final = 2
"""Length-delimited wire type for string, bytes, embedded messages, packed repeated fields."""

WIRE_TYPE_32BIT: Final = 5
"""32-bit wire type for fixed32, sfixed32, float."""


class ProtobufDecodeError(ValueError):
    """Raised when protobuf data cannot be decoded."""


def _decode_length_at(data: bytes, pos: int) -> tuple[int, int]:
    """Decode a length varint and validate bounds.

    Returns:
        (length, new_position) tuple.

    Raises:
        ProtobufDecodeError: If the length exceeds available data.
    """
    length, consumed = decode_varint(data, pos)
    new_pos = pos + consumed
    if new_pos + length > len(data):
        raise ProtobufDecodeError(
            f"Length field {length} at position {pos} exceeds data size {len(data)}"
        )
    return length, new_pos


def encode_tag(field_number: int, wire_type: int) -> bytes:
    """Encode a protobuf field tag."""
    return encode_varint((field_number << 3) | wire_type)


def decode_tag(data: bytes, pos: int) -> tuple[int, int, int]:
    """
    Decode a protobuf field tag.

    Returns:
        (field_number, wire_type, new_position) tuple.
    """
    tag, consumed = decode_varint(data, pos)
    return tag >> 3, tag & 0x07, pos + consumed


def encode_length_delimited(field_number: int, data: bytes) -> bytes:
    """Encode a length-delimited field (string, bytes, embedded message)."""
    return encode_tag(field_number, WIRE_TYPE_LENGTH_DELIMITED) + encode_varint(len(data)) + data


def encode_string(field_number: int, value: str) -> bytes:
    """Encode a string field."""
    return encode_length_delimited(field_number, value.encode("utf-8"))


def encode_bytes(field_number: int, value: bytes) -> bytes:
    """Encode a bytes field."""
    return encode_length_delimited(field_number, value)


def encode_bool(field_number: int, value: bool) -> bytes:
    """Encode a bool field."""
    return encode_tag(field_number, WIRE_TYPE_VARINT) + encode_varint(1 if value else 0)


def encode_uint64(field_number: int, value: int) -> bytes:
    """Encode a uint64 field."""
    return encode_tag(field_number, WIRE_TYPE_VARINT) + encode_varint(value)


@dataclass(slots=True)
class SubOpts:
    """Subscription option for a topic."""

    subscribe: bool
    """True to subscribe, False to unsubscribe."""

    topic_id: TopicId
    """Topic identifier."""

    def encode(self) -> bytes:
        """Encode as protobuf."""
        result = bytearray()
        result.extend(encode_bool(1, self.subscribe))
        result.extend(encode_string(2, self.topic_id))
        return bytes(result)

    @classmethod
    def decode(cls, data: bytes) -> SubOpts:
        """Decode from protobuf."""
        subscribe = False
        topic_id = TopicId("")
        pos = 0

        while pos < len(data):
            field_num, wire_type, pos = decode_tag(data, pos)

            if field_num == 1 and wire_type == WIRE_TYPE_VARINT:
                value, consumed = decode_varint(data, pos)
                pos += consumed
                subscribe = value != 0
            elif field_num == 2 and wire_type == WIRE_TYPE_LENGTH_DELIMITED:
                length, pos = _decode_length_at(data, pos)
                topic_id = TopicId(data[pos : pos + length].decode("utf-8"))
                pos += length
            else:
                pos = _skip_field(data, pos, wire_type)

        return cls(subscribe=subscribe, topic_id=topic_id)


@dataclass(slots=True)
class Message:
    """A published gossipsub message."""

    from_peer: bytes = b""
    """Sender peer ID (optional in anonymous mode)."""

    data: bytes = b""
    """Message payload."""

    seqno: bytes = b""
    """Sequence number (optional)."""

    topic: TopicId = TopicId("")
    """Topic this message belongs to."""

    signature: bytes = b""
    """Signature over message fields (optional)."""

    key: bytes = b""
    """Sender's public key (optional)."""

    def encode(self) -> bytes:
        """Encode as protobuf."""
        result = bytearray()
        if self.from_peer:
            result.extend(encode_bytes(1, self.from_peer))
        if self.data:
            result.extend(encode_bytes(2, self.data))
        if self.seqno:
            result.extend(encode_bytes(3, self.seqno))
        if self.topic:
            result.extend(encode_string(4, self.topic))
        if self.signature:
            result.extend(encode_bytes(5, self.signature))
        if self.key:
            result.extend(encode_bytes(6, self.key))
        return bytes(result)

    @classmethod
    def decode(cls, data: bytes) -> Message:
        """Decode from protobuf."""
        message = cls()
        pos = 0

        while pos < len(data):
            field_num, wire_type, pos = decode_tag(data, pos)

            if wire_type == WIRE_TYPE_LENGTH_DELIMITED:
                length, pos = _decode_length_at(data, pos)
                field_data = data[pos : pos + length]
                pos += length

                if field_num == 1:
                    message.from_peer = field_data
                elif field_num == 2:
                    message.data = field_data
                elif field_num == 3:
                    message.seqno = field_data
                elif field_num == 4:
                    message.topic = TopicId(field_data.decode("utf-8"))
                elif field_num == 5:
                    message.signature = field_data
                elif field_num == 6:
                    message.key = field_data
            else:
                pos = _skip_field(data, pos, wire_type)

        return message


@dataclass(slots=True)
class ControlIHave:
    """IHAVE control message - advertise cached message IDs."""

    topic_id: TopicId = TopicId("")
    """Topic the messages belong to."""

    message_ids: list[bytes] = field(default_factory=list)
    """Message IDs available for this topic."""

    def encode(self) -> bytes:
        """Encode as protobuf."""
        result = bytearray()
        if self.topic_id:
            result.extend(encode_string(1, self.topic_id))
        for message_id in self.message_ids:
            result.extend(encode_bytes(2, message_id))
        return bytes(result)

    @classmethod
    def decode(cls, data: bytes) -> ControlIHave:
        """Decode from protobuf."""
        topic_id = TopicId("")
        message_ids: list[bytes] = []
        pos = 0

        while pos < len(data):
            field_num, wire_type, pos = decode_tag(data, pos)

            if wire_type == WIRE_TYPE_LENGTH_DELIMITED:
                length, pos = _decode_length_at(data, pos)
                field_data = data[pos : pos + length]
                pos += length

                if field_num == 1:
                    topic_id = TopicId(field_data.decode("utf-8"))
                elif field_num == 2:
                    message_ids.append(field_data)
            else:
                pos = _skip_field(data, pos, wire_type)

        return cls(topic_id=topic_id, message_ids=message_ids)


@dataclass(slots=True)
class ControlIWant:
    """IWANT control message - request full messages by ID."""

    message_ids: list[bytes] = field(default_factory=list)
    """Message IDs being requested."""

    def encode(self) -> bytes:
        """Encode as protobuf."""
        result = bytearray()
        for message_id in self.message_ids:
            result.extend(encode_bytes(1, message_id))
        return bytes(result)

    @classmethod
    def decode(cls, data: bytes) -> ControlIWant:
        """Decode from protobuf."""
        message_ids: list[bytes] = []
        pos = 0

        while pos < len(data):
            field_num, wire_type, pos = decode_tag(data, pos)

            if field_num == 1 and wire_type == WIRE_TYPE_LENGTH_DELIMITED:
                length, pos = _decode_length_at(data, pos)
                message_ids.append(data[pos : pos + length])
                pos += length
            else:
                pos = _skip_field(data, pos, wire_type)

        return cls(message_ids=message_ids)


@dataclass(slots=True)
class ControlGraft:
    """GRAFT control message - request to join mesh for topic."""

    topic_id: TopicId = TopicId("")
    """Topic to join mesh for."""

    def encode(self) -> bytes:
        """Encode as protobuf."""
        result = bytearray()
        if self.topic_id:
            result.extend(encode_string(1, self.topic_id))
        return bytes(result)

    @classmethod
    def decode(cls, data: bytes) -> ControlGraft:
        """Decode from protobuf."""
        topic_id = TopicId("")
        pos = 0

        while pos < len(data):
            field_num, wire_type, pos = decode_tag(data, pos)

            if field_num == 1 and wire_type == WIRE_TYPE_LENGTH_DELIMITED:
                length, pos = _decode_length_at(data, pos)
                topic_id = TopicId(data[pos : pos + length].decode("utf-8"))
                pos += length
            else:
                pos = _skip_field(data, pos, wire_type)

        return cls(topic_id=topic_id)


@dataclass(slots=True)
class ControlPrune:
    """PRUNE control message - notification of mesh removal."""

    topic_id: TopicId = TopicId("")
    """Topic being pruned from."""

    backoff: int = 0
    """Backoff duration in seconds before re-grafting (v1.1)."""

    def encode(self) -> bytes:
        """Encode as protobuf."""
        result = bytearray()
        if self.topic_id:
            result.extend(encode_string(1, self.topic_id))
        if self.backoff > 0:
            result.extend(encode_uint64(3, self.backoff))
        return bytes(result)

    @classmethod
    def decode(cls, data: bytes) -> ControlPrune:
        """Decode from protobuf."""
        topic_id = TopicId("")
        backoff = 0
        pos = 0

        while pos < len(data):
            field_num, wire_type, pos = decode_tag(data, pos)

            if field_num == 1 and wire_type == WIRE_TYPE_LENGTH_DELIMITED:
                length, pos = _decode_length_at(data, pos)
                topic_id = TopicId(data[pos : pos + length].decode("utf-8"))
                pos += length
            elif field_num == 3 and wire_type == WIRE_TYPE_VARINT:
                backoff, consumed = decode_varint(data, pos)
                pos += consumed
            else:
                pos = _skip_field(data, pos, wire_type)

        return cls(topic_id=topic_id, backoff=backoff)


@dataclass(slots=True)
class ControlIDontWant:
    """IDONTWANT control message - decline specific messages (v1.2)."""

    message_ids: list[bytes] = field(default_factory=list)
    """Message IDs the sender does not want."""

    def encode(self) -> bytes:
        """Encode as protobuf."""
        result = bytearray()
        for message_id in self.message_ids:
            result.extend(encode_bytes(1, message_id))
        return bytes(result)

    @classmethod
    def decode(cls, data: bytes) -> ControlIDontWant:
        """Decode from protobuf."""
        message_ids: list[bytes] = []
        pos = 0

        while pos < len(data):
            field_num, wire_type, pos = decode_tag(data, pos)

            if field_num == 1 and wire_type == WIRE_TYPE_LENGTH_DELIMITED:
                length, pos = _decode_length_at(data, pos)
                message_ids.append(data[pos : pos + length])
                pos += length
            else:
                pos = _skip_field(data, pos, wire_type)

        return cls(message_ids=message_ids)


@dataclass(slots=True)
class ControlMessage:
    """Container for all control message types."""

    ihave: list[ControlIHave] = field(default_factory=list)
    """IHAVE messages advertising cached message IDs."""

    iwant: list[ControlIWant] = field(default_factory=list)
    """IWANT messages requesting full messages."""

    graft: list[ControlGraft] = field(default_factory=list)
    """GRAFT messages requesting mesh membership."""

    prune: list[ControlPrune] = field(default_factory=list)
    """PRUNE messages notifying mesh removal."""

    idontwant: list[ControlIDontWant] = field(default_factory=list)
    """IDONTWANT messages declining specific messages (v1.2)."""

    def encode(self) -> bytes:
        """Encode as protobuf."""
        result = bytearray()
        for ihave in self.ihave:
            result.extend(encode_length_delimited(1, ihave.encode()))
        for iwant in self.iwant:
            result.extend(encode_length_delimited(2, iwant.encode()))
        for graft in self.graft:
            result.extend(encode_length_delimited(3, graft.encode()))
        for prune in self.prune:
            result.extend(encode_length_delimited(4, prune.encode()))
        for idw in self.idontwant:
            result.extend(encode_length_delimited(5, idw.encode()))
        return bytes(result)

    @classmethod
    def decode(cls, data: bytes) -> ControlMessage:
        """Decode from protobuf."""
        ctrl = cls()
        pos = 0

        while pos < len(data):
            field_num, wire_type, pos = decode_tag(data, pos)

            if wire_type == WIRE_TYPE_LENGTH_DELIMITED:
                length, pos = _decode_length_at(data, pos)
                field_data = data[pos : pos + length]
                pos += length

                if field_num == 1:
                    ctrl.ihave.append(ControlIHave.decode(field_data))
                elif field_num == 2:
                    ctrl.iwant.append(ControlIWant.decode(field_data))
                elif field_num == 3:
                    ctrl.graft.append(ControlGraft.decode(field_data))
                elif field_num == 4:
                    ctrl.prune.append(ControlPrune.decode(field_data))
                elif field_num == 5:
                    ctrl.idontwant.append(ControlIDontWant.decode(field_data))
            else:
                pos = _skip_field(data, pos, wire_type)

        return ctrl

    def is_empty(self) -> bool:
        """Check if this control message contains no data."""
        return not (self.ihave or self.iwant or self.graft or self.prune or self.idontwant)


@dataclass(slots=True)
class RPC:
    """
    Top-level gossipsub RPC message.

    An RPC contains subscriptions, published messages, and control messages
    all bundled together for efficiency.
    """

    subscriptions: list[SubOpts] = field(default_factory=list)
    """Subscription changes (subscribe/unsubscribe)."""

    publish: list[Message] = field(default_factory=list)
    """Messages being published."""

    control: ControlMessage | None = None
    """Control messages (GRAFT, PRUNE, IHAVE, IWANT, IDONTWANT)."""

    def encode(self) -> bytes:
        """
        Encode as protobuf.

        The encoding follows standard protobuf wire format::

            field 1: repeated SubOpts subscriptions
            field 2: repeated Message publish
            field 3: optional ControlMessage control
        """
        result = bytearray()

        for sub in self.subscriptions:
            result.extend(encode_length_delimited(1, sub.encode()))

        for message in self.publish:
            result.extend(encode_length_delimited(2, message.encode()))

        if self.control and not self.control.is_empty():
            result.extend(encode_length_delimited(3, self.control.encode()))

        return bytes(result)

    @classmethod
    def decode(cls, data: bytes) -> RPC:
        """Decode from protobuf."""
        rpc = cls()
        pos = 0

        while pos < len(data):
            field_num, wire_type, pos = decode_tag(data, pos)

            if wire_type == WIRE_TYPE_LENGTH_DELIMITED:
                length, pos = _decode_length_at(data, pos)
                field_data = data[pos : pos + length]
                pos += length

                if field_num == 1:
                    rpc.subscriptions.append(SubOpts.decode(field_data))
                elif field_num == 2:
                    rpc.publish.append(Message.decode(field_data))
                elif field_num == 3:
                    rpc.control = ControlMessage.decode(field_data)
            else:
                pos = _skip_field(data, pos, wire_type)

        return rpc

    @classmethod
    def subscription(cls, topics: list[TopicId], subscribe: bool = True) -> RPC:
        """
        Create an RPC with subscription messages.

        Args:
            topics: List of topic IDs to subscribe/unsubscribe.
            subscribe: True to subscribe, False to unsubscribe.
        """
        return cls(subscriptions=[SubOpts(subscribe=subscribe, topic_id=t) for t in topics])

    @classmethod
    def graft(cls, topics: list[TopicId]) -> RPC:
        """
        Create an RPC with GRAFT control messages.

        Args:
            topics: List of topic IDs to request mesh membership for.
        """
        return cls(control=ControlMessage(graft=[ControlGraft(topic_id=t) for t in topics]))


def _skip_field(data: bytes, pos: int, wire_type: int) -> int:
    """Skip an unknown field based on wire type.

    Raises:
        ProtobufDecodeError: If the wire type is unrecognized (e.g. deprecated
            group types 3/4) and cannot be skipped.
    """
    if wire_type == WIRE_TYPE_VARINT:
        _, consumed = decode_varint(data, pos)
        pos += consumed
    elif wire_type == WIRE_TYPE_LENGTH_DELIMITED:
        length, pos = _decode_length_at(data, pos)
        pos += length
    elif wire_type == WIRE_TYPE_32BIT:
        pos += 4
    elif wire_type == WIRE_TYPE_64BIT:
        pos += 8
    else:
        raise ProtobufDecodeError(f"Unknown wire type: {wire_type}")
    return pos
