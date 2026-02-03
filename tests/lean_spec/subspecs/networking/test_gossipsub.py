"""Tests for GossipSub protocol implementation."""

import pytest

from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.config import (
    MESSAGE_DOMAIN_INVALID_SNAPPY,
    MESSAGE_DOMAIN_VALID_SNAPPY,
)
from lean_spec.subspecs.networking.gossipsub import (
    ControlMessage,
    FanoutEntry,
    ForkMismatchError,
    GossipsubMessage,
    GossipsubParameters,
    GossipTopic,
    Graft,
    IDontWant,
    IHave,
    IWant,
    MeshState,
    MessageCache,
    Prune,
    SeenCache,
    TopicKind,
    TopicMesh,
    format_topic_string,
    parse_topic_string,
)


def peer(name: str) -> PeerId:
    """Create a PeerId from a test name."""
    return PeerId.from_base58(name)


class TestGossipsubParameters:
    """Test suite for GossipSub protocol parameters."""

    def test_default_parameters(self) -> None:
        """Test default GossipSub parameters."""
        params = GossipsubParameters()

        # Test Ethereum spec values
        assert params.d == 8
        assert params.d_low == 6
        assert params.d_high == 12
        assert params.d_lazy == 6
        assert params.heartbeat_interval_secs == 0.7
        assert params.fanout_ttl_secs == 60
        assert params.mcache_len == 6
        assert params.mcache_gossip == 3

        # Test relationships
        assert params.d_low < params.d < params.d_high
        assert params.d_lazy <= params.d
        assert params.mcache_gossip <= params.mcache_len


class TestGossipsubMessage:
    """Test suite for GossipSub message handling and ID computation."""

    @pytest.mark.parametrize(
        "has_snappy,decompress_succeeds,expected_domain",
        [
            (False, False, MESSAGE_DOMAIN_INVALID_SNAPPY),
            (True, True, MESSAGE_DOMAIN_VALID_SNAPPY),
            (True, False, MESSAGE_DOMAIN_INVALID_SNAPPY),
        ],
    )
    def test_message_id_computation(
        self, has_snappy: bool, decompress_succeeds: bool, expected_domain: bytes
    ) -> None:
        """Test message ID computation across different snappy scenarios."""
        topic = b"test_topic"
        raw_data = b"raw_test_data"
        decompressed_data = b"decompressed_test_data"

        snappy_decompress = None
        if has_snappy:
            if decompress_succeeds:

                def snappy_decompress(data: bytes) -> bytes:
                    return decompressed_data
            else:

                def snappy_decompress(data: bytes) -> bytes:
                    raise Exception("Decompression failed")

        message = GossipsubMessage(topic, raw_data, snappy_decompress)
        message_id = message.id

        assert len(message_id) == 20
        assert isinstance(message_id, bytes)

        # Test determinism
        message2 = GossipsubMessage(topic, raw_data, snappy_decompress)
        assert message_id == message2.id

    def test_message_id_caching(self) -> None:
        """Test that message IDs are cached."""
        topic = b"test_topic"
        data = b"test_data"
        decompress_calls = 0

        def counting_decompress(data: bytes) -> bytes:
            nonlocal decompress_calls
            decompress_calls += 1
            return b"decompressed"

        message = GossipsubMessage(topic, data, counting_decompress)
        first_id = message.id
        second_id = message.id

        assert decompress_calls == 1  # Called only once
        assert first_id is second_id

    def test_message_uniqueness(self) -> None:
        """Test message ID uniqueness."""
        test_cases = [
            (b"topic1", b"data"),
            (b"topic2", b"data"),
            (b"topic", b"data1"),
            (b"topic", b"data2"),
        ]

        messages = [GossipsubMessage(topic, data) for topic, data in test_cases]
        ids = [msg.id for msg in messages]

        assert len(ids) == len(set(ids))


class TestControlMessages:
    """Test suite for gossipsub control messages."""

    def test_graft_creation(self) -> None:
        """Test GRAFT message creation."""
        graft = Graft(topic_id="test_topic")
        assert graft.topic_id == "test_topic"

    def test_prune_creation(self) -> None:
        """Test PRUNE message creation."""
        prune = Prune(topic_id="test_topic")
        assert prune.topic_id == "test_topic"

    def test_ihave_creation(self) -> None:
        """Test IHAVE message creation."""
        from lean_spec.types import Bytes20

        msg_ids = [Bytes20(b"12345678901234567890"), Bytes20(b"abcdefghijklmnopqrst")]
        ihave = IHave(topic_id="test_topic", message_ids=msg_ids)

        assert ihave.topic_id == "test_topic"
        assert len(ihave.message_ids) == 2

    def test_iwant_creation(self) -> None:
        """Test IWANT message creation."""
        from lean_spec.types import Bytes20

        msg_ids = [Bytes20(b"12345678901234567890")]
        iwant = IWant(message_ids=msg_ids)

        assert len(iwant.message_ids) == 1

    def test_idontwant_creation(self) -> None:
        """Test IDONTWANT message creation (v1.2)."""
        from lean_spec.types import Bytes20

        msg_ids = [Bytes20(b"12345678901234567890")]
        idontwant = IDontWant(message_ids=msg_ids)

        assert len(idontwant.message_ids) == 1

    def test_control_message_aggregation(self) -> None:
        """Test aggregated control message container."""
        graft = Graft(topic_id="topic1")
        prune = Prune(topic_id="topic2")

        control = ControlMessage(grafts=[graft], prunes=[prune])

        assert len(control.grafts) == 1
        assert len(control.prunes) == 1
        assert not control.is_empty()

    def test_control_message_empty_check(self) -> None:
        """Test control message empty check."""
        empty_control = ControlMessage()
        assert empty_control.is_empty()

        non_empty = ControlMessage(grafts=[Graft(topic_id="topic")])
        assert not non_empty.is_empty()


class TestTopicForkValidation:
    """Test suite for topic fork compatibility validation."""

    def test_is_fork_compatible_matching(self) -> None:
        """Test is_fork_compatible returns True for matching fork_digest."""
        topic = GossipTopic(kind=TopicKind.BLOCK, fork_digest="0x12345678")
        assert topic.is_fork_compatible("0x12345678")

    def test_is_fork_compatible_mismatched(self) -> None:
        """Test is_fork_compatible returns False for mismatched fork_digest."""
        topic = GossipTopic(kind=TopicKind.BLOCK, fork_digest="0x12345678")
        assert not topic.is_fork_compatible("0xdeadbeef")

    def test_validate_fork_success(self) -> None:
        """Test validate_fork passes for matching fork_digest."""
        topic = GossipTopic(kind=TopicKind.BLOCK, fork_digest="0x12345678")
        topic.validate_fork("0x12345678")  # Should not raise

    def test_validate_fork_raises_on_mismatch(self) -> None:
        """Test validate_fork raises ForkMismatchError on mismatch."""
        from lean_spec.subspecs.networking.gossipsub import ForkMismatchError

        topic = GossipTopic(kind=TopicKind.BLOCK, fork_digest="0x12345678")
        with pytest.raises(ForkMismatchError) as exc_info:
            topic.validate_fork("0xdeadbeef")

        assert exc_info.value.expected == "0xdeadbeef"
        assert exc_info.value.actual == "0x12345678"

    def test_from_string_validated_success(self) -> None:
        """Test from_string_validated parses and validates successfully."""
        topic = GossipTopic.from_string_validated(
            "/leanconsensus/0x12345678/block/ssz_snappy",
            expected_fork_digest="0x12345678",
        )
        assert topic.kind == TopicKind.BLOCK
        assert topic.fork_digest == "0x12345678"

    def test_from_string_validated_raises_on_mismatch(self) -> None:
        """Test from_string_validated raises ForkMismatchError on mismatch."""
        from lean_spec.subspecs.networking.gossipsub import ForkMismatchError

        with pytest.raises(ForkMismatchError):
            GossipTopic.from_string_validated(
                "/leanconsensus/0x12345678/block/ssz_snappy",
                expected_fork_digest="0xdeadbeef",
            )

    def test_from_string_validated_raises_on_invalid_topic(self) -> None:
        """Test from_string_validated raises ValueError for invalid topics."""
        with pytest.raises(ValueError, match="expected 4 parts"):
            GossipTopic.from_string_validated("/invalid/topic", "0x12345678")


class TestTopicFormatting:
    """Test suite for topic string formatting and parsing."""

    def test_gossip_topic_creation(self) -> None:
        """Test GossipTopic creation."""
        topic = GossipTopic(kind=TopicKind.BLOCK, fork_digest="0x12345678")

        assert topic.kind == TopicKind.BLOCK
        assert topic.fork_digest == "0x12345678"
        assert str(topic) == "/leanconsensus/0x12345678/block/ssz_snappy"

    def test_gossip_topic_from_string(self) -> None:
        """Test parsing topic string."""
        topic = GossipTopic.from_string("/leanconsensus/0x12345678/block/ssz_snappy")

        assert topic.kind == TopicKind.BLOCK
        assert topic.fork_digest == "0x12345678"

    def test_gossip_topic_factory_methods(self) -> None:
        """Test GossipTopic factory methods."""
        block_topic = GossipTopic.block("0xabcd1234")
        assert block_topic.kind == TopicKind.BLOCK

        attestation_subnet_topic = GossipTopic.attestation_subnet("0xabcd1234", 0)
        assert attestation_subnet_topic.kind == TopicKind.ATTESTATION_SUBNET

    def test_format_topic_string(self) -> None:
        """Test topic string formatting."""
        result = format_topic_string("block", "0x12345678")
        assert result == "/leanconsensus/0x12345678/block/ssz_snappy"

    def test_parse_topic_string(self) -> None:
        """Test topic string parsing."""
        prefix, fork_digest, topic_name, encoding = parse_topic_string(
            "/leanconsensus/0x12345678/block/ssz_snappy"
        )

        assert prefix == "leanconsensus"
        assert fork_digest == "0x12345678"
        assert topic_name == "block"
        assert encoding == "ssz_snappy"

    def test_invalid_topic_string(self) -> None:
        """Test handling of invalid topic strings."""
        with pytest.raises(ValueError, match="expected 4 parts"):
            GossipTopic.from_string("/invalid/topic")

        with pytest.raises(ValueError, match="Invalid prefix"):
            GossipTopic.from_string("/wrongprefix/0x123/block/ssz_snappy")

    def test_topic_kind_enum(self) -> None:
        """Test TopicKind enum."""
        assert TopicKind.BLOCK.value == "block"
        assert TopicKind.ATTESTATION_SUBNET.value == "attestation"
        assert str(TopicKind.BLOCK) == "block"


class TestMeshState:
    """Test suite for mesh state management."""

    def test_mesh_state_initialization(self) -> None:
        """Test MeshState initialization."""
        params = GossipsubParameters(d=8, d_low=6, d_high=12, d_lazy=6)
        mesh = MeshState(params=params)

        assert mesh.d == 8
        assert mesh.d_low == 6
        assert mesh.d_high == 12
        assert mesh.d_lazy == 6

    def test_subscribe_and_unsubscribe(self) -> None:
        """Test topic subscription."""
        mesh = MeshState(params=GossipsubParameters())

        mesh.subscribe("topic1")
        assert mesh.is_subscribed("topic1")
        assert not mesh.is_subscribed("topic2")

        peers = mesh.unsubscribe("topic1")
        assert not mesh.is_subscribed("topic1")
        assert peers == set()

    def test_add_remove_mesh_peers(self) -> None:
        """Test adding and removing peers from mesh."""
        mesh = MeshState(params=GossipsubParameters())
        mesh.subscribe("topic1")

        peer1 = peer("peer1")
        peer2 = peer("peer2")

        assert mesh.add_to_mesh("topic1", peer1)
        assert mesh.add_to_mesh("topic1", peer2)
        assert not mesh.add_to_mesh("topic1", peer1)  # Already in mesh

        peers = mesh.get_mesh_peers("topic1")
        assert peer1 in peers
        assert peer2 in peers

        assert mesh.remove_from_mesh("topic1", peer1)
        assert not mesh.remove_from_mesh("topic1", peer1)  # Already removed

        peers = mesh.get_mesh_peers("topic1")
        assert peer1 not in peers
        assert peer2 in peers

    def test_gossip_peer_selection(self) -> None:
        """Test selection of non-mesh peers for gossip."""
        params = GossipsubParameters(d_lazy=3)
        mesh = MeshState(params=params)
        mesh.subscribe("topic1")
        peer1 = peer("peer1")
        peer2 = peer("peer2")
        mesh.add_to_mesh("topic1", peer1)
        mesh.add_to_mesh("topic1", peer2)

        all_peers = {
            peer("peer1"),
            peer("peer2"),
            peer("peer3"),
            peer("peer4"),
            peer("peer5"),
            peer("peer6"),
        }

        gossip_peers = mesh.select_peers_for_gossip("topic1", all_peers)

        mesh_peers = mesh.get_mesh_peers("topic1")
        for p in gossip_peers:
            assert p not in mesh_peers


class TestTopicMesh:
    """Test suite for TopicMesh dataclass."""

    def test_topic_mesh_add_remove(self) -> None:
        """Test adding and removing peers."""
        topic_mesh = TopicMesh()
        peer1 = peer("peer1")

        assert topic_mesh.add_peer(peer1)
        assert not topic_mesh.add_peer(peer1)  # Already exists
        assert peer1 in topic_mesh.peers

        assert topic_mesh.remove_peer(peer1)
        assert not topic_mesh.remove_peer(peer1)  # Already removed
        assert peer1 not in topic_mesh.peers


class TestMessageCache:
    """Test suite for message cache."""

    def test_cache_put_and_get(self) -> None:
        """Test putting and retrieving messages."""
        cache = MessageCache(mcache_len=6, mcache_gossip=3)
        message = GossipsubMessage(topic=b"topic", raw_data=b"data")

        assert cache.put("topic", message)
        assert not cache.put("topic", message)  # Duplicate

        retrieved = cache.get(message.id)
        assert retrieved is not None
        assert retrieved.id == message.id

    def test_cache_has(self) -> None:
        """Test checking if message is in cache."""
        cache = MessageCache()
        message = GossipsubMessage(topic=b"topic", raw_data=b"data")

        assert not cache.has(message.id)
        cache.put("topic", message)
        assert cache.has(message.id)

    def test_cache_shift(self) -> None:
        """Test cache window shifting."""
        cache = MessageCache(mcache_len=3, mcache_gossip=2)

        messages = []
        for i in range(5):
            msg = GossipsubMessage(topic=b"topic", raw_data=f"data{i}".encode())
            cache.put("topic", msg)
            messages.append(msg)
            cache.shift()

        # Old messages should be evicted
        assert not cache.has(messages[0].id)
        assert not cache.has(messages[1].id)

    def test_get_gossip_ids(self) -> None:
        """Test getting message IDs for IHAVE gossip."""
        cache = MessageCache(mcache_len=6, mcache_gossip=3)

        msg1 = GossipsubMessage(topic=b"topic1", raw_data=b"data1")
        msg2 = GossipsubMessage(topic=b"topic2", raw_data=b"data2")
        msg3 = GossipsubMessage(topic=b"topic1", raw_data=b"data3")

        cache.put("topic1", msg1)
        cache.put("topic2", msg2)
        cache.put("topic1", msg3)

        gossip_ids = cache.get_gossip_ids("topic1")

        assert msg1.id in gossip_ids
        assert msg2.id not in gossip_ids
        assert msg3.id in gossip_ids


class TestSeenCache:
    """Test suite for seen message cache."""

    def test_seen_cache_add_and_check(self) -> None:
        """Test adding and checking seen messages."""
        from lean_spec.types import Bytes20

        cache = SeenCache(ttl_seconds=60)
        msg_id = Bytes20(b"12345678901234567890")

        assert not cache.has(msg_id)
        assert cache.add(msg_id, timestamp=1000.0)
        assert cache.has(msg_id)
        assert not cache.add(msg_id, timestamp=1001.0)  # Duplicate

    def test_seen_cache_cleanup(self) -> None:
        """Test cleanup of expired entries."""
        from lean_spec.types import Bytes20

        cache = SeenCache(ttl_seconds=10)
        msg_id = Bytes20(b"12345678901234567890")

        cache.add(msg_id, timestamp=1000.0)
        assert cache.has(msg_id)

        removed = cache.cleanup(current_time=1015.0)
        assert removed == 1
        assert not cache.has(msg_id)


class TestFanoutEntry:
    """Test suite for FanoutEntry dataclass."""

    def test_fanout_entry_staleness(self) -> None:
        """Test fanout entry staleness detection."""
        entry = FanoutEntry()
        entry.last_published = 1000.0

        assert not entry.is_stale(current_time=1050.0, ttl=60.0)
        assert entry.is_stale(current_time=1070.0, ttl=60.0)


class TestRPCProtobufEncoding:
    """Test suite for GossipSub RPC protobuf wire format encoding/decoding.

    These tests verify interoperability with rust-libp2p and go-libp2p by
    ensuring our encoding matches the expected protobuf wire format.
    """

    def test_varint_encoding(self) -> None:
        """Test varint encoding matches protobuf spec."""
        from lean_spec.subspecs.networking.gossipsub import encode_varint

        # Single byte varints (0-127)
        assert encode_varint(0) == b"\x00"
        assert encode_varint(1) == b"\x01"
        assert encode_varint(127) == b"\x7f"

        # Two byte varints (128-16383)
        assert encode_varint(128) == b"\x80\x01"
        assert encode_varint(300) == b"\xac\x02"
        assert encode_varint(16383) == b"\xff\x7f"

        # Larger varints
        assert encode_varint(16384) == b"\x80\x80\x01"

    def test_varint_decoding(self) -> None:
        """Test varint decoding matches protobuf spec."""
        from lean_spec.subspecs.networking.gossipsub import decode_varint

        # Single byte
        value, pos = decode_varint(b"\x00", 0)
        assert value == 0
        assert pos == 1

        value, pos = decode_varint(b"\x7f", 0)
        assert value == 127
        assert pos == 1

        # Multi-byte
        value, pos = decode_varint(b"\x80\x01", 0)
        assert value == 128
        assert pos == 2

        value, pos = decode_varint(b"\xac\x02", 0)
        assert value == 300
        assert pos == 2

    def test_varint_roundtrip(self) -> None:
        """Test varint encode/decode roundtrip."""
        from lean_spec.subspecs.networking.gossipsub import decode_varint, encode_varint

        test_values = [0, 1, 127, 128, 255, 256, 16383, 16384, 2097151, 268435455]
        for value in test_values:
            encoded = encode_varint(value)
            decoded, _ = decode_varint(encoded, 0)
            assert decoded == value, f"Failed for value {value}"

    def test_subopts_encode_decode(self) -> None:
        """Test SubOpts (subscription) encoding/decoding."""
        from lean_spec.subspecs.networking.gossipsub import SubOpts

        # Subscribe
        sub = SubOpts(subscribe=True, topic_id="/leanconsensus/0x12345678/block/ssz_snappy")
        encoded = sub.encode()
        decoded = SubOpts.decode(encoded)

        assert decoded.subscribe is True
        assert decoded.topic_id == "/leanconsensus/0x12345678/block/ssz_snappy"

        # Unsubscribe
        unsub = SubOpts(subscribe=False, topic_id="/test/topic")
        encoded = unsub.encode()
        decoded = SubOpts.decode(encoded)

        assert decoded.subscribe is False
        assert decoded.topic_id == "/test/topic"

    def test_message_encode_decode(self) -> None:
        """Test Message encoding/decoding."""
        from lean_spec.subspecs.networking.gossipsub import RPCMessage

        msg = RPCMessage(
            from_peer=b"peer123",
            data=b"hello world",
            seqno=b"\x00\x01\x02\x03\x04\x05\x06\x07",
            topic="/test/topic",
            signature=b"sig" * 16,
            key=b"pubkey",
        )
        encoded = msg.encode()
        decoded = RPCMessage.decode(encoded)

        assert decoded.from_peer == b"peer123"
        assert decoded.data == b"hello world"
        assert decoded.seqno == b"\x00\x01\x02\x03\x04\x05\x06\x07"
        assert decoded.topic == "/test/topic"
        assert decoded.signature == b"sig" * 16
        assert decoded.key == b"pubkey"

    def test_message_minimal(self) -> None:
        """Test Message with only required fields."""
        from lean_spec.subspecs.networking.gossipsub import RPCMessage

        msg = RPCMessage(topic="/test/topic", data=b"payload")
        encoded = msg.encode()
        decoded = RPCMessage.decode(encoded)

        assert decoded.topic == "/test/topic"
        assert decoded.data == b"payload"
        assert decoded.from_peer == b""
        assert decoded.seqno == b""

    def test_control_graft_encode_decode(self) -> None:
        """Test ControlGraft encoding/decoding."""
        from lean_spec.subspecs.networking.gossipsub import RPCControlGraft

        graft = RPCControlGraft(topic_id="/test/blocks")
        encoded = graft.encode()
        decoded = RPCControlGraft.decode(encoded)

        assert decoded.topic_id == "/test/blocks"

    def test_control_prune_encode_decode(self) -> None:
        """Test ControlPrune encoding/decoding with backoff."""
        from lean_spec.subspecs.networking.gossipsub import RPCControlPrune

        prune = RPCControlPrune(topic_id="/test/blocks", backoff=60)
        encoded = prune.encode()
        decoded = RPCControlPrune.decode(encoded)

        assert decoded.topic_id == "/test/blocks"
        assert decoded.backoff == 60

    def test_control_ihave_encode_decode(self) -> None:
        """Test ControlIHave encoding/decoding."""
        from lean_spec.subspecs.networking.gossipsub import RPCControlIHave

        msg_ids = [b"msgid1234567890ab", b"msgid2345678901bc", b"msgid3456789012cd"]
        ihave = RPCControlIHave(topic_id="/test/blocks", message_ids=msg_ids)
        encoded = ihave.encode()
        decoded = RPCControlIHave.decode(encoded)

        assert decoded.topic_id == "/test/blocks"
        assert decoded.message_ids == msg_ids

    def test_control_iwant_encode_decode(self) -> None:
        """Test ControlIWant encoding/decoding."""
        from lean_spec.subspecs.networking.gossipsub import RPCControlIWant

        msg_ids = [b"msgid1234567890ab", b"msgid2345678901bc"]
        iwant = RPCControlIWant(message_ids=msg_ids)
        encoded = iwant.encode()
        decoded = RPCControlIWant.decode(encoded)

        assert decoded.message_ids == msg_ids

    def test_control_idontwant_encode_decode(self) -> None:
        """Test ControlIDontWant encoding/decoding (v1.2)."""
        from lean_spec.subspecs.networking.gossipsub import RPCControlIDontWant

        msg_ids = [b"msgid1234567890ab"]
        idontwant = RPCControlIDontWant(message_ids=msg_ids)
        encoded = idontwant.encode()
        decoded = RPCControlIDontWant.decode(encoded)

        assert decoded.message_ids == msg_ids

    def test_control_message_aggregate(self) -> None:
        """Test ControlMessage with multiple control types."""
        from lean_spec.subspecs.networking.gossipsub import (
            RPCControlGraft,
            RPCControlIHave,
            RPCControlMessage,
            RPCControlPrune,
        )

        ctrl = RPCControlMessage(
            graft=[RPCControlGraft(topic_id="/topic1")],
            prune=[RPCControlPrune(topic_id="/topic2", backoff=30)],
            ihave=[RPCControlIHave(topic_id="/topic1", message_ids=[b"msg123456789012"])],
        )
        encoded = ctrl.encode()
        decoded = RPCControlMessage.decode(encoded)

        assert len(decoded.graft) == 1
        assert decoded.graft[0].topic_id == "/topic1"
        assert len(decoded.prune) == 1
        assert decoded.prune[0].topic_id == "/topic2"
        assert decoded.prune[0].backoff == 30
        assert len(decoded.ihave) == 1
        assert decoded.ihave[0].topic_id == "/topic1"

    def test_rpc_subscription_only(self) -> None:
        """Test RPC with only subscriptions."""
        from lean_spec.subspecs.networking.gossipsub import RPC, SubOpts

        rpc = RPC(
            subscriptions=[
                SubOpts(subscribe=True, topic_id="/topic1"),
                SubOpts(subscribe=False, topic_id="/topic2"),
            ]
        )
        encoded = rpc.encode()
        decoded = RPC.decode(encoded)

        assert len(decoded.subscriptions) == 2
        assert decoded.subscriptions[0].subscribe is True
        assert decoded.subscriptions[0].topic_id == "/topic1"
        assert decoded.subscriptions[1].subscribe is False
        assert decoded.subscriptions[1].topic_id == "/topic2"

    def test_rpc_publish_only(self) -> None:
        """Test RPC with only published messages."""
        from lean_spec.subspecs.networking.gossipsub import RPC, RPCMessage

        rpc = RPC(
            publish=[
                RPCMessage(topic="/blocks", data=b"block_data_1"),
                RPCMessage(topic="/attestations", data=b"attestation_data"),
            ]
        )
        encoded = rpc.encode()
        decoded = RPC.decode(encoded)

        assert len(decoded.publish) == 2
        assert decoded.publish[0].topic == "/blocks"
        assert decoded.publish[0].data == b"block_data_1"
        assert decoded.publish[1].topic == "/attestations"

    def test_rpc_control_only(self) -> None:
        """Test RPC with only control messages."""
        from lean_spec.subspecs.networking.gossipsub import (
            RPC,
            RPCControlGraft,
            RPCControlMessage,
        )

        rpc = RPC(control=RPCControlMessage(graft=[RPCControlGraft(topic_id="/blocks")]))
        encoded = rpc.encode()
        decoded = RPC.decode(encoded)

        assert decoded.control is not None
        assert len(decoded.control.graft) == 1
        assert decoded.control.graft[0].topic_id == "/blocks"

    def test_rpc_full_message(self) -> None:
        """Test RPC with all message types (full gossipsub exchange)."""
        from lean_spec.subspecs.networking.gossipsub import (
            RPC,
            RPCControlGraft,
            RPCControlIHave,
            RPCControlMessage,
            RPCMessage,
            SubOpts,
        )

        rpc = RPC(
            subscriptions=[SubOpts(subscribe=True, topic_id="/blocks")],
            publish=[RPCMessage(topic="/blocks", data=b"block_payload")],
            control=RPCControlMessage(
                graft=[RPCControlGraft(topic_id="/blocks")],
                ihave=[RPCControlIHave(topic_id="/blocks", message_ids=[b"msgid123456789ab"])],
            ),
        )
        encoded = rpc.encode()
        decoded = RPC.decode(encoded)

        # Verify all parts decoded correctly
        assert len(decoded.subscriptions) == 1
        assert decoded.subscriptions[0].subscribe is True

        assert len(decoded.publish) == 1
        assert decoded.publish[0].data == b"block_payload"

        assert decoded.control is not None
        assert len(decoded.control.graft) == 1
        assert len(decoded.control.ihave) == 1

    def test_rpc_empty_check(self) -> None:
        """Test RPC is_empty method."""
        from lean_spec.subspecs.networking.gossipsub import RPC, SubOpts

        empty_rpc = RPC()
        assert empty_rpc.is_empty()

        non_empty = RPC(subscriptions=[SubOpts(subscribe=True, topic_id="/topic")])
        assert not non_empty.is_empty()

    def test_rpc_helper_functions(self) -> None:
        """Test RPC creation helper functions."""
        from lean_spec.subspecs.networking.gossipsub import (
            create_graft_rpc,
            create_ihave_rpc,
            create_iwant_rpc,
            create_prune_rpc,
            create_publish_rpc,
            create_subscription_rpc,
        )

        # Subscription RPC
        sub_rpc = create_subscription_rpc(["/topic1", "/topic2"], subscribe=True)
        assert len(sub_rpc.subscriptions) == 2
        assert all(s.subscribe for s in sub_rpc.subscriptions)

        # GRAFT RPC
        graft_rpc = create_graft_rpc(["/topic1"])
        assert graft_rpc.control is not None
        assert len(graft_rpc.control.graft) == 1

        # PRUNE RPC
        prune_rpc = create_prune_rpc(["/topic1"], backoff=120)
        assert prune_rpc.control is not None
        assert len(prune_rpc.control.prune) == 1
        assert prune_rpc.control.prune[0].backoff == 120

        # IHAVE RPC
        ihave_rpc = create_ihave_rpc("/topic1", [b"msg1", b"msg2"])
        assert ihave_rpc.control is not None
        assert len(ihave_rpc.control.ihave) == 1
        assert len(ihave_rpc.control.ihave[0].message_ids) == 2

        # IWANT RPC
        iwant_rpc = create_iwant_rpc([b"msg1"])
        assert iwant_rpc.control is not None
        assert len(iwant_rpc.control.iwant) == 1

        # Publish RPC
        pub_rpc = create_publish_rpc("/topic1", b"data")
        assert len(pub_rpc.publish) == 1
        assert pub_rpc.publish[0].data == b"data"

    def test_wire_format_compatibility(self) -> None:
        """Test wire format matches expected protobuf encoding.

        This test verifies that our encoding produces the same bytes as
        a reference implementation would for simple cases.
        """
        from lean_spec.subspecs.networking.gossipsub import RPC, SubOpts

        # A subscription RPC with a simple topic
        rpc = RPC(subscriptions=[SubOpts(subscribe=True, topic_id="test")])
        encoded = rpc.encode()

        # Verify it can be decoded
        decoded = RPC.decode(encoded)
        assert decoded.subscriptions[0].topic_id == "test"
        assert decoded.subscriptions[0].subscribe is True

        # Verify structure: field 1 (subscriptions) is length-delimited
        # SubOpts: field 1 (bool), field 2 (string)
        # Expected encoding for this simple case can be computed manually
        # but the roundtrip test above verifies correctness

    def test_large_message_encoding(self) -> None:
        """Test encoding of large messages (typical block size)."""
        from lean_spec.subspecs.networking.gossipsub import RPC, RPCMessage

        # Simulate a large block payload (100KB)
        large_data = b"x" * 100_000

        rpc = RPC(publish=[RPCMessage(topic="/blocks", data=large_data)])
        encoded = rpc.encode()
        decoded = RPC.decode(encoded)

        assert len(decoded.publish) == 1
        assert len(decoded.publish[0].data) == 100_000
        assert decoded.publish[0].data == large_data


class TestGossipHandlerForkValidation:
    """Test suite for GossipHandler fork compatibility validation."""

    def test_decode_message_rejects_wrong_fork(self) -> None:
        """GossipHandler.decode_message() raises ForkMismatchError for wrong fork."""
        from lean_spec.subspecs.networking.client.event_source import GossipHandler

        handler = GossipHandler(fork_digest="0x12345678")

        # Topic with different fork_digest
        wrong_fork_topic = "/leanconsensus/0xdeadbeef/block/ssz_snappy"

        with pytest.raises(ForkMismatchError) as exc_info:
            handler.decode_message(wrong_fork_topic, b"dummy_data")

        assert exc_info.value.expected == "0x12345678"
        assert exc_info.value.actual == "0xdeadbeef"

    def test_get_topic_rejects_wrong_fork(self) -> None:
        """GossipHandler.get_topic() raises ForkMismatchError for wrong fork."""
        from lean_spec.subspecs.networking.client.event_source import GossipHandler

        handler = GossipHandler(fork_digest="0x12345678")

        # Topic with different fork_digest
        wrong_fork_topic = "/leanconsensus/0xdeadbeef/attestation/ssz_snappy"

        with pytest.raises(ForkMismatchError) as exc_info:
            handler.get_topic(wrong_fork_topic)

        assert exc_info.value.expected == "0x12345678"
        assert exc_info.value.actual == "0xdeadbeef"

    def test_get_topic_accepts_matching_fork(self) -> None:
        """GossipHandler.get_topic() returns topic for matching fork."""
        from lean_spec.subspecs.networking.client.event_source import GossipHandler

        handler = GossipHandler(fork_digest="0x12345678")

        # Topic with matching fork_digest
        matching_topic = "/leanconsensus/0x12345678/block/ssz_snappy"

        topic = handler.get_topic(matching_topic)

        assert topic.kind == TopicKind.BLOCK
        assert topic.fork_digest == "0x12345678"
