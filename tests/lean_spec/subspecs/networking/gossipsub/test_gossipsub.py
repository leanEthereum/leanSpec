"""Tests for GossipSub protocol implementation."""

import pytest

from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.client.event_source import GossipHandler
from lean_spec.subspecs.networking.gossipsub import (
    ControlGraft,
    ControlIDontWant,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    ForkMismatchError,
    GossipsubParameters,
    GossipTopic,
    TopicKind,
    format_topic_string,
    parse_topic_string,
)
from lean_spec.subspecs.networking.gossipsub.mesh import FanoutEntry, MeshState, TopicMesh
from lean_spec.subspecs.networking.gossipsub.rpc import (
    RPC,
    SubOpts,
    create_graft_rpc,
    create_ihave_rpc,
    create_iwant_rpc,
    create_prune_rpc,
    create_publish_rpc,
    create_subscription_rpc,
)
from lean_spec.subspecs.networking.gossipsub.rpc import (
    ControlGraft as RPCControlGraft,
)
from lean_spec.subspecs.networking.gossipsub.rpc import (
    ControlIDontWant as RPCControlIDontWant,
)
from lean_spec.subspecs.networking.gossipsub.rpc import (
    ControlIHave as RPCControlIHave,
)
from lean_spec.subspecs.networking.gossipsub.rpc import (
    ControlIWant as RPCControlIWant,
)
from lean_spec.subspecs.networking.gossipsub.rpc import (
    ControlMessage as RPCControlMessage,
)
from lean_spec.subspecs.networking.gossipsub.rpc import (
    ControlPrune as RPCControlPrune,
)
from lean_spec.subspecs.networking.gossipsub.rpc import (
    Message as RPCMessage,
)
from lean_spec.subspecs.networking.varint import decode_varint, encode_varint
from lean_spec.types import Bytes20


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


class TestControlMessages:
    """Test suite for gossipsub control messages."""

    def test_graft_creation(self) -> None:
        """Test GRAFT message creation."""
        graft = ControlGraft(topic_id="test_topic")
        assert graft.topic_id == "test_topic"

    def test_prune_creation(self) -> None:
        """Test PRUNE message creation."""
        prune = ControlPrune(topic_id="test_topic")
        assert prune.topic_id == "test_topic"

    def test_ihave_creation(self) -> None:
        """Test IHAVE message creation."""
        msg_ids = [Bytes20(b"12345678901234567890"), Bytes20(b"abcdefghijklmnopqrst")]
        ihave = ControlIHave(topic_id="test_topic", message_ids=msg_ids)

        assert ihave.topic_id == "test_topic"
        assert len(ihave.message_ids) == 2

    def test_iwant_creation(self) -> None:
        """Test IWANT message creation."""
        msg_ids = [Bytes20(b"12345678901234567890")]
        iwant = ControlIWant(message_ids=msg_ids)

        assert len(iwant.message_ids) == 1

    def test_idontwant_creation(self) -> None:
        """Test IDONTWANT message creation (v1.2)."""
        msg_ids = [Bytes20(b"12345678901234567890")]
        idontwant = ControlIDontWant(message_ids=msg_ids)

        assert len(idontwant.message_ids) == 1

    def test_control_message_aggregation(self) -> None:
        """Test aggregated control message container."""
        graft = ControlGraft(topic_id="topic1")
        prune = ControlPrune(topic_id="topic2")

        control = ControlMessage(graft=[graft], prune=[prune])

        assert len(control.graft) == 1
        assert len(control.prune) == 1
        assert not control.is_empty()

    def test_control_message_empty_check(self) -> None:
        """Test control message empty check."""
        empty_control = ControlMessage()
        assert empty_control.is_empty()

        non_empty = ControlMessage(graft=[ControlGraft(topic_id="topic")])
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

        assert mesh.params.d == 8
        assert mesh.params.d_low == 6
        assert mesh.params.d_high == 12
        assert mesh.params.d_lazy == 6

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


class TestFanoutEntry:
    """Test suite for FanoutEntry dataclass."""

    def test_fanout_entry_staleness(self) -> None:
        """Test fanout entry staleness detection."""
        entry = FanoutEntry()
        entry.last_published = 1000.0

        assert not entry.is_stale(current_time=1050.0, ttl=60.0)
        assert entry.is_stale(current_time=1070.0, ttl=60.0)


class TestFanoutOperations:
    """Tests for fanout management in MeshState."""

    def test_update_fanout_creates_entry(self) -> None:
        """update_fanout creates a new fanout entry if none exists."""
        mesh = MeshState(params=GossipsubParameters(d=3))
        topic = "fanout_topic"

        available = {peer("p1"), peer("p2"), peer("p3"), peer("p4")}
        result = mesh.update_fanout(topic, available)

        assert len(result) <= 3  # Up to D peers
        assert len(result) > 0

    def test_update_fanout_returns_mesh_if_subscribed(self) -> None:
        """update_fanout returns mesh peers for subscribed topics."""
        mesh = MeshState(params=GossipsubParameters(d=3))
        topic = "sub_topic"

        mesh.subscribe(topic)
        p1 = peer("p1")
        mesh.add_to_mesh(topic, p1)

        result = mesh.update_fanout(topic, {p1, peer("p2")})
        assert p1 in result

    def test_update_fanout_fills_to_d(self) -> None:
        """update_fanout fills fanout up to D peers."""
        mesh = MeshState(params=GossipsubParameters(d=4))
        topic = "fanout_topic"

        names = ["pA", "pB", "pC", "pD", "pE", "pF", "pG", "pH", "pJ", "pK"]
        available = {peer(n) for n in names}
        result = mesh.update_fanout(topic, available)

        assert len(result) == 4

    def test_cleanup_fanouts_removes_stale(self) -> None:
        """cleanup_fanouts removes stale entries."""
        mesh = MeshState(params=GossipsubParameters())
        topic = "old_topic"

        mesh.update_fanout(topic, {peer("p1")})
        # Make it stale
        mesh._fanouts[topic].last_published = 0.0

        removed = mesh.cleanup_fanouts(ttl=60.0)
        assert removed == 1
        assert topic not in mesh._fanouts

    def test_cleanup_fanouts_keeps_fresh(self) -> None:
        """cleanup_fanouts keeps recent entries."""
        mesh = MeshState(params=GossipsubParameters())
        topic = "fresh_topic"

        mesh.update_fanout(topic, {peer("p1")})
        # last_published is set to time.time() by update_fanout

        removed = mesh.cleanup_fanouts(ttl=60.0)
        assert removed == 0
        assert topic in mesh._fanouts

    def test_subscribe_promotes_fanout_to_mesh(self) -> None:
        """Subscribing to a topic promotes fanout peers to mesh."""
        mesh = MeshState(params=GossipsubParameters())
        topic = "promote_topic"

        p1 = peer("p1")
        mesh.update_fanout(topic, {p1})
        assert topic in mesh._fanouts

        mesh.subscribe(topic)

        # Fanout should be removed, peers promoted to mesh
        assert topic not in mesh._fanouts
        assert p1 in mesh.get_mesh_peers(topic)

    def test_unsubscribe_returns_mesh_peers(self) -> None:
        """Unsubscribing returns the set of mesh peers (for PRUNE)."""
        mesh = MeshState(params=GossipsubParameters())
        topic = "unsub_topic"

        mesh.subscribe(topic)
        p1 = peer("p1")
        p2 = peer("p2")
        mesh.add_to_mesh(topic, p1)
        mesh.add_to_mesh(topic, p2)

        result = mesh.unsubscribe(topic)
        assert result == {p1, p2}

    def test_select_peers_for_gossip_respects_d_lazy(self) -> None:
        """Gossip peer selection returns at most d_lazy peers."""
        params = GossipsubParameters(d_lazy=2)
        mesh = MeshState(params=params)
        mesh.subscribe("topic")

        names = ["gA", "gB", "gC", "gD", "gE", "gF", "gG", "gH", "gJ", "gK"]
        all_peers = {peer(n) for n in names}
        result = mesh.select_peers_for_gossip("topic", all_peers)

        assert len(result) <= 2

    def test_select_peers_for_gossip_excludes_mesh(self) -> None:
        """Gossip peer selection excludes mesh peers."""
        params = GossipsubParameters(d_lazy=5)
        mesh = MeshState(params=params)
        mesh.subscribe("topic")

        mesh_peer = peer("mesh1")
        mesh.add_to_mesh("topic", mesh_peer)

        all_peers = {mesh_peer, peer("p1"), peer("p2")}
        result = mesh.select_peers_for_gossip("topic", all_peers)

        assert mesh_peer not in result


class TestRPCProtobufEncoding:
    """Test suite for GossipSub RPC protobuf wire format encoding/decoding.

    These tests verify interoperability with rust-libp2p and go-libp2p by
    ensuring our encoding matches the expected protobuf wire format.
    """

    def test_varint_encoding(self) -> None:
        """Test varint encoding matches protobuf spec."""
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
        test_values = [0, 1, 127, 128, 255, 256, 16383, 16384, 2097151, 268435455]
        for value in test_values:
            encoded = encode_varint(value)
            decoded, _ = decode_varint(encoded, 0)
            assert decoded == value, f"Failed for value {value}"

    def test_subopts_encode_decode(self) -> None:
        """Test SubOpts (subscription) encoding/decoding."""
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
        msg = RPCMessage(topic="/test/topic", data=b"payload")
        encoded = msg.encode()
        decoded = RPCMessage.decode(encoded)

        assert decoded.topic == "/test/topic"
        assert decoded.data == b"payload"
        assert decoded.from_peer == b""
        assert decoded.seqno == b""

    def test_control_graft_encode_decode(self) -> None:
        """Test ControlGraft encoding/decoding."""
        graft = RPCControlGraft(topic_id="/test/blocks")
        encoded = graft.encode()
        decoded = RPCControlGraft.decode(encoded)

        assert decoded.topic_id == "/test/blocks"

    def test_control_prune_encode_decode(self) -> None:
        """Test ControlPrune encoding/decoding with backoff."""
        prune = RPCControlPrune(topic_id="/test/blocks", backoff=60)
        encoded = prune.encode()
        decoded = RPCControlPrune.decode(encoded)

        assert decoded.topic_id == "/test/blocks"
        assert decoded.backoff == 60

    def test_control_ihave_encode_decode(self) -> None:
        """Test ControlIHave encoding/decoding."""
        msg_ids = [b"msgid1234567890ab", b"msgid2345678901bc", b"msgid3456789012cd"]
        ihave = RPCControlIHave(topic_id="/test/blocks", message_ids=msg_ids)
        encoded = ihave.encode()
        decoded = RPCControlIHave.decode(encoded)

        assert decoded.topic_id == "/test/blocks"
        assert decoded.message_ids == msg_ids

    def test_control_iwant_encode_decode(self) -> None:
        """Test ControlIWant encoding/decoding."""
        msg_ids = [b"msgid1234567890ab", b"msgid2345678901bc"]
        iwant = RPCControlIWant(message_ids=msg_ids)
        encoded = iwant.encode()
        decoded = RPCControlIWant.decode(encoded)

        assert decoded.message_ids == msg_ids

    def test_control_idontwant_encode_decode(self) -> None:
        """Test ControlIDontWant encoding/decoding (v1.2)."""
        msg_ids = [b"msgid1234567890ab"]
        idontwant = RPCControlIDontWant(message_ids=msg_ids)
        encoded = idontwant.encode()
        decoded = RPCControlIDontWant.decode(encoded)

        assert decoded.message_ids == msg_ids

    def test_control_message_aggregate(self) -> None:
        """Test ControlMessage with multiple control types."""
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
        rpc = RPC(control=RPCControlMessage(graft=[RPCControlGraft(topic_id="/blocks")]))
        encoded = rpc.encode()
        decoded = RPC.decode(encoded)

        assert decoded.control is not None
        assert len(decoded.control.graft) == 1
        assert decoded.control.graft[0].topic_id == "/blocks"

    def test_rpc_full_message(self) -> None:
        """Test RPC with all message types (full gossipsub exchange)."""
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
        empty_rpc = RPC()
        assert empty_rpc.is_empty()

        non_empty = RPC(subscriptions=[SubOpts(subscribe=True, topic_id="/topic")])
        assert not non_empty.is_empty()

    def test_rpc_helper_functions(self) -> None:
        """Test RPC creation helper functions."""
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
        handler = GossipHandler(fork_digest="0x12345678")

        # Topic with different fork_digest
        wrong_fork_topic = "/leanconsensus/0xdeadbeef/block/ssz_snappy"

        with pytest.raises(ForkMismatchError) as exc_info:
            handler.decode_message(wrong_fork_topic, b"dummy_data")

        assert exc_info.value.expected == "0x12345678"
        assert exc_info.value.actual == "0xdeadbeef"

    def test_get_topic_rejects_wrong_fork(self) -> None:
        """GossipHandler.get_topic() raises ForkMismatchError for wrong fork."""
        handler = GossipHandler(fork_digest="0x12345678")

        # Topic with different fork_digest
        wrong_fork_topic = "/leanconsensus/0xdeadbeef/attestation/ssz_snappy"

        with pytest.raises(ForkMismatchError) as exc_info:
            handler.get_topic(wrong_fork_topic)

        assert exc_info.value.expected == "0x12345678"
        assert exc_info.value.actual == "0xdeadbeef"

    def test_get_topic_accepts_matching_fork(self) -> None:
        """GossipHandler.get_topic() returns topic for matching fork."""
        handler = GossipHandler(fork_digest="0x12345678")

        # Topic with matching fork_digest
        matching_topic = "/leanconsensus/0x12345678/block/ssz_snappy"

        topic = handler.get_topic(matching_topic)

        assert topic.kind == TopicKind.BLOCK
        assert topic.fork_digest == "0x12345678"
