"""Tests for gossipsub RPC protobuf edge cases."""

from __future__ import annotations

import pytest

from lean_spec.node.networking.gossipsub.rpc import (
    RPC,
    WIRE_TYPE_32BIT,
    WIRE_TYPE_64BIT,
    WIRE_TYPE_LENGTH_DELIMITED,
    WIRE_TYPE_VARINT,
    ControlGraft,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    Message,
    ProtobufDecodeError,
    SubOpts,
    _skip_field,
    encode_bytes,
    encode_tag,
)
from lean_spec.node.networking.gossipsub.types import TopicId


class TestSkipField:
    """Tests for _skip_field across all wire types."""

    def test_skip_varint(self) -> None:
        """Skip a varint field."""
        # Encode a varint value (300 = 0xAC 0x02)
        data = b"\xac\x02"
        new_pos = _skip_field(data, 0, WIRE_TYPE_VARINT)
        assert new_pos == 2

    def test_skip_length_delimited(self) -> None:
        """Skip a length-delimited field."""
        # Length 3, then 3 bytes of data
        data = b"\x03abc"
        new_pos = _skip_field(data, 0, WIRE_TYPE_LENGTH_DELIMITED)
        assert new_pos == 4

    def test_skip_32bit(self) -> None:
        """Skip a 32-bit fixed field."""
        data = b"\x00\x00\x00\x00"
        new_pos = _skip_field(data, 0, WIRE_TYPE_32BIT)
        assert new_pos == 4

    def test_skip_64bit(self) -> None:
        """Skip a 64-bit fixed field."""
        data = b"\x00" * 8
        new_pos = _skip_field(data, 0, WIRE_TYPE_64BIT)
        assert new_pos == 8

    def test_skip_unknown_wire_type_raises(self) -> None:
        """Unknown wire type raises ProtobufDecodeError."""
        with pytest.raises(ProtobufDecodeError, match="Unknown wire type"):
            _skip_field(b"\x00", 0, 3)

    def test_skip_deprecated_group_type_raises(self) -> None:
        """Deprecated group wire type (4) raises ProtobufDecodeError."""
        with pytest.raises(ProtobufDecodeError, match="Unknown wire type"):
            _skip_field(b"\x00", 0, 4)


class TestEmptyDecode:
    """Tests for decoding empty bytes."""

    def test_rpc_decode_empty(self) -> None:
        """Decoding empty bytes returns an empty RPC."""
        assert RPC.decode(b"") == RPC()

    def test_message_decode_empty(self) -> None:
        """Decoding empty bytes returns a default Message."""
        assert Message.decode(b"") == Message()

    def test_control_message_decode_empty(self) -> None:
        """Decoding empty bytes returns an empty ControlMessage."""
        ctrl = ControlMessage.decode(b"")
        assert ctrl == ControlMessage()
        assert ctrl.is_empty()

    def test_subopts_decode_empty(self) -> None:
        """Decoding empty bytes returns default SubOpts."""
        assert SubOpts.decode(b"") == SubOpts(subscribe=False, topic_id=TopicId(""))


class TestForwardCompatibility:
    """Tests for decoding with unknown fields (forward compat)."""

    def test_rpc_with_unknown_varint_field(self) -> None:
        """RPC ignores unknown varint fields."""
        rpc = RPC(subscriptions=[SubOpts(subscribe=True, topic_id=TopicId("topic"))])
        data = bytearray(rpc.encode())

        # Append unknown field 99, wire type varint, value 42.
        data.extend(encode_tag(99, WIRE_TYPE_VARINT))
        data.extend(b"\x2a")  # varint 42

        assert RPC.decode(bytes(data)) == rpc

    def test_message_with_unknown_field(self) -> None:
        """Message ignores unknown length-delimited fields."""
        message = Message(topic=TopicId("t"), data=b"d")
        data = bytearray(message.encode())

        # Append unknown field 99.
        data.extend(encode_bytes(99, b"unknown_data"))

        assert Message.decode(bytes(data)) == message


class TestLengthValidation:
    """Tests for protobuf length field bounds checking."""

    def test_truncated_length_delimited_field(self) -> None:
        """Truncated length-delimited data raises ProtobufDecodeError."""
        # Field 1, wire type 2 (length-delimited), length=100 but only 3 bytes.
        data = encode_tag(1, WIRE_TYPE_LENGTH_DELIMITED) + b"\x64abc"

        with pytest.raises(ProtobufDecodeError, match="exceeds data size"):
            SubOpts.decode(data)

    def test_truncated_rpc_field(self) -> None:
        """RPC with truncated field raises ProtobufDecodeError."""
        data = encode_tag(1, WIRE_TYPE_LENGTH_DELIMITED) + b"\xff\x01"

        with pytest.raises(ProtobufDecodeError, match="exceeds data size"):
            RPC.decode(data)


class TestMultiTopicControl:
    """Tests for multiple topics in a single control message."""

    def test_multi_topic_graft(self) -> None:
        """Multiple GRAFTs in one control message roundtrip correctly."""
        ctrl = ControlMessage(
            graft=[
                ControlGraft(topic_id=TopicId("/topicA")),
                ControlGraft(topic_id=TopicId("/topicB")),
                ControlGraft(topic_id=TopicId("/topicC")),
            ]
        )
        assert ControlMessage.decode(ctrl.encode()) == ctrl

    def test_full_control_message_all_types(self) -> None:
        """Control message with all types in a single message."""
        ctrl = ControlMessage(
            ihave=[ControlIHave(topic_id=TopicId("/t"), message_ids=[b"id12345678901234"])],
            iwant=[ControlIWant(message_ids=[b"id12345678901234"])],
            graft=[ControlGraft(topic_id=TopicId("/t"))],
            prune=[ControlPrune(topic_id=TopicId("/t"), backoff=30)],
        )
        assert ControlMessage.decode(ctrl.encode()) == ctrl

    def test_rpc_with_multiple_subscriptions_and_messages(self) -> None:
        """RPC with multiple subscriptions and published messages."""
        rpc = RPC(
            subscriptions=[
                SubOpts(subscribe=True, topic_id=TopicId("/a")),
                SubOpts(subscribe=False, topic_id=TopicId("/b")),
                SubOpts(subscribe=True, topic_id=TopicId("/c")),
            ],
            publish=[
                Message(topic=TopicId("/a"), data=b"msg1"),
                Message(topic=TopicId("/c"), data=b"msg2"),
            ],
        )
        assert RPC.decode(rpc.encode()) == rpc
