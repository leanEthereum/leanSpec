"""Tests for gossipsub RPC protobuf wire format encoding and decoding."""

from __future__ import annotations

import pytest

from lean_spec.node.networking.gossipsub.rpc import (
    RPC,
    WIRE_TYPE_32BIT,
    WIRE_TYPE_64BIT,
    WIRE_TYPE_LENGTH_DELIMITED,
    WIRE_TYPE_VARINT,
    ControlGraft,
    ControlIDontWant,
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


class TestControlMessages:
    """Test suite for gossipsub control messages."""

    def test_control_message_empty_check(self) -> None:
        """Test control message empty check."""
        empty_control = ControlMessage()
        assert empty_control.is_empty()

        non_empty = ControlMessage(graft=[ControlGraft(topic_id=TopicId("topic"))])
        assert not non_empty.is_empty()


class TestRPCProtobufEncoding:
    """
    Test suite for GossipSub RPC protobuf wire format encoding/decoding.

    These tests verify interoperability with rust-libp2p and go-libp2p by
    ensuring our encoding matches the expected protobuf wire format.
    """

    def test_subopts_encode_decode(self) -> None:
        """Test SubOpts (subscription) encoding/decoding."""
        sub = SubOpts(
            subscribe=True,
            topic_id=TopicId("/leanconsensus/0x12345678/block/ssz_snappy"),
        )
        assert SubOpts.decode(sub.encode()) == sub

        unsub = SubOpts(subscribe=False, topic_id=TopicId("/test/topic"))
        assert SubOpts.decode(unsub.encode()) == unsub

    def test_message_encode_decode(self) -> None:
        """Test Message encoding/decoding."""
        message = Message(
            from_peer=b"peer123",
            data=b"hello world",
            seqno=b"\x00\x01\x02\x03\x04\x05\x06\x07",
            topic=TopicId("/test/topic"),
            signature=b"sig" * 16,
            key=b"pubkey",
        )
        assert Message.decode(message.encode()) == message

    def test_message_minimal(self) -> None:
        """Test Message with only required fields."""
        message = Message(topic=TopicId("/test/topic"), data=b"payload")
        assert Message.decode(message.encode()) == message

    def test_control_graft_encode_decode(self) -> None:
        """Test ControlGraft encoding/decoding."""
        graft = ControlGraft(topic_id=TopicId("/test/blocks"))
        assert ControlGraft.decode(graft.encode()) == graft

    def test_control_prune_encode_decode(self) -> None:
        """Test ControlPrune encoding/decoding with backoff."""
        prune = ControlPrune(topic_id=TopicId("/test/blocks"), backoff=60)
        assert ControlPrune.decode(prune.encode()) == prune

    def test_control_ihave_encode_decode(self) -> None:
        """Test ControlIHave encoding/decoding."""
        ihave = ControlIHave(
            topic_id=TopicId("/test/blocks"),
            message_ids=[b"msgid1234567890ab", b"msgid2345678901bc", b"msgid3456789012cd"],
        )
        assert ControlIHave.decode(ihave.encode()) == ihave

    def test_control_iwant_encode_decode(self) -> None:
        """Test ControlIWant encoding/decoding."""
        iwant = ControlIWant(message_ids=[b"msgid1234567890ab", b"msgid2345678901bc"])
        assert ControlIWant.decode(iwant.encode()) == iwant

    def test_control_idontwant_encode_decode(self) -> None:
        """Test ControlIDontWant encoding/decoding (v1.2)."""
        idontwant = ControlIDontWant(message_ids=[b"msgid1234567890ab"])
        assert ControlIDontWant.decode(idontwant.encode()) == idontwant

    def test_control_message_aggregate(self) -> None:
        """Test ControlMessage with multiple control types."""
        ctrl = ControlMessage(
            graft=[ControlGraft(topic_id=TopicId("/topic1"))],
            prune=[ControlPrune(topic_id=TopicId("/topic2"), backoff=30)],
            ihave=[ControlIHave(topic_id=TopicId("/topic1"), message_ids=[b"msg123456789012"])],
        )
        assert ControlMessage.decode(ctrl.encode()) == ctrl

    def test_rpc_subscription_only(self) -> None:
        """Test RPC with only subscriptions."""
        rpc = RPC(
            subscriptions=[
                SubOpts(subscribe=True, topic_id=TopicId("/topic1")),
                SubOpts(subscribe=False, topic_id=TopicId("/topic2")),
            ]
        )
        assert RPC.decode(rpc.encode()) == rpc

    def test_rpc_publish_only(self) -> None:
        """Test RPC with only published messages."""
        rpc = RPC(
            publish=[
                Message(topic=TopicId("/blocks"), data=b"block_data_1"),
                Message(topic=TopicId("/attestations"), data=b"attestation_data"),
            ]
        )
        assert RPC.decode(rpc.encode()) == rpc

    def test_rpc_control_only(self) -> None:
        """Test RPC with only control messages."""
        rpc = RPC(control=ControlMessage(graft=[ControlGraft(topic_id=TopicId("/blocks"))]))
        assert RPC.decode(rpc.encode()) == rpc

    def test_rpc_full_message(self) -> None:
        """Test RPC with all message types (full gossipsub exchange)."""
        rpc = RPC(
            subscriptions=[SubOpts(subscribe=True, topic_id=TopicId("/blocks"))],
            publish=[Message(topic=TopicId("/blocks"), data=b"block_payload")],
            control=ControlMessage(
                graft=[ControlGraft(topic_id=TopicId("/blocks"))],
                ihave=[
                    ControlIHave(topic_id=TopicId("/blocks"), message_ids=[b"msgid123456789ab"])
                ],
            ),
        )
        assert RPC.decode(rpc.encode()) == rpc

    def test_rpc_helper_functions(self) -> None:
        """Test RPC creation helper functions."""
        assert RPC.subscription([TopicId("/topic1"), TopicId("/topic2")], subscribe=True) == RPC(
            subscriptions=[
                SubOpts(subscribe=True, topic_id=TopicId("/topic1")),
                SubOpts(subscribe=True, topic_id=TopicId("/topic2")),
            ]
        )

        assert RPC.graft([TopicId("/topic1")]) == RPC(
            control=ControlMessage(graft=[ControlGraft(topic_id=TopicId("/topic1"))])
        )

    def test_wire_format_compatibility(self) -> None:
        """
        Test wire format matches expected protobuf encoding.

        Verifies that our encoding produces bytes that round-trip
        correctly through decode, matching the original structure.
        """
        rpc = RPC(subscriptions=[SubOpts(subscribe=True, topic_id=TopicId("test"))])
        assert RPC.decode(rpc.encode()) == rpc

    def test_large_message_encoding(self) -> None:
        """Test encoding of large messages (typical block size)."""
        rpc = RPC(publish=[Message(topic=TopicId("/blocks"), data=b"x" * 100_000)])
        assert RPC.decode(rpc.encode()) == rpc


class TestSkipField:
    """Tests for _skip_field across all wire types."""

    def test_skip_varint(self) -> None:
        """Skip a varint field."""
        # Encode a varint value (300 = 0xAC 0x02)
        encoded_field = b"\xac\x02"
        new_pos = _skip_field(encoded_field, 0, WIRE_TYPE_VARINT)
        assert new_pos == 2

    def test_skip_length_delimited(self) -> None:
        """Skip a length-delimited field."""
        # Length 3, then 3 bytes of data
        encoded_field = b"\x03abc"
        new_pos = _skip_field(encoded_field, 0, WIRE_TYPE_LENGTH_DELIMITED)
        assert new_pos == 4

    def test_skip_32bit(self) -> None:
        """Skip a 32-bit fixed field."""
        encoded_field = b"\x00\x00\x00\x00"
        new_pos = _skip_field(encoded_field, 0, WIRE_TYPE_32BIT)
        assert new_pos == 4

    def test_skip_64bit(self) -> None:
        """Skip a 64-bit fixed field."""
        encoded_field = b"\x00" * 8
        new_pos = _skip_field(encoded_field, 0, WIRE_TYPE_64BIT)
        assert new_pos == 8

    def test_skip_unknown_wire_type_raises(self) -> None:
        """Unknown wire type raises ProtobufDecodeError."""
        with pytest.raises(ProtobufDecodeError) as exception_info:
            _skip_field(b"\x00", 0, 3)
        assert str(exception_info.value) == "Unknown wire type: 3"

    def test_skip_deprecated_group_type_raises(self) -> None:
        """Deprecated group wire type (4) raises ProtobufDecodeError."""
        with pytest.raises(ProtobufDecodeError) as exception_info:
            _skip_field(b"\x00", 0, 4)
        assert str(exception_info.value) == "Unknown wire type: 4"


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
        encoded_rpc = bytearray(rpc.encode())

        # Append unknown field 99, wire type varint, value 42.
        encoded_rpc.extend(encode_tag(99, WIRE_TYPE_VARINT))
        encoded_rpc.extend(b"\x2a")  # varint 42

        assert RPC.decode(bytes(encoded_rpc)) == rpc

    def test_message_with_unknown_field(self) -> None:
        """Message ignores unknown length-delimited fields."""
        message = Message(topic=TopicId("t"), data=b"d")
        encoded_message = bytearray(message.encode())

        # Append unknown field 99.
        encoded_message.extend(encode_bytes(99, b"unknown_data"))

        assert Message.decode(bytes(encoded_message)) == message


class TestLengthValidation:
    """Tests for protobuf length field bounds checking."""

    def test_truncated_length_delimited_field(self) -> None:
        """Truncated length-delimited data raises ProtobufDecodeError."""
        # Field 1, wire type 2 (length-delimited), length=100 but only 3 bytes.
        encoded_field = encode_tag(1, WIRE_TYPE_LENGTH_DELIMITED) + b"\x64abc"

        with pytest.raises(ProtobufDecodeError) as exception_info:
            SubOpts.decode(encoded_field)
        assert str(exception_info.value) == "Length field 100 at position 1 exceeds data size 5"

    def test_truncated_rpc_field(self) -> None:
        """RPC with truncated field raises ProtobufDecodeError."""
        encoded_rpc = encode_tag(1, WIRE_TYPE_LENGTH_DELIMITED) + b"\xff\x01"

        with pytest.raises(ProtobufDecodeError) as exception_info:
            RPC.decode(encoded_rpc)
        assert str(exception_info.value) == "Length field 255 at position 1 exceeds data size 3"


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
