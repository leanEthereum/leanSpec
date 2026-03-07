"""Tests for GossipSub protocol implementation."""

import pytest

from lean_spec.subspecs.containers.validator import SubnetId
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.client.event_source import GossipHandler
from lean_spec.subspecs.networking.gossipsub import (
    ForkMismatchError,
    GossipsubParameters,
    GossipTopic,
    TopicKind,
    parse_topic_string,
)
from lean_spec.subspecs.networking.gossipsub.mesh import FanoutEntry, MeshState, TopicMesh
from lean_spec.subspecs.networking.gossipsub.rpc import (
    RPC,
    ControlGraft,
    ControlIDontWant,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    Message,
    SubOpts,
)
from lean_spec.subspecs.networking.gossipsub.types import TopicId


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

    def test_control_message_empty_check(self) -> None:
        """Test control message empty check."""
        empty_control = ControlMessage()
        assert empty_control.is_empty()

        non_empty = ControlMessage(graft=[ControlGraft(topic_id=TopicId("topic"))])
        assert not non_empty.is_empty()


class TestTopicForkValidation:
    """Test suite for topic fork compatibility validation."""

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
        assert GossipTopic.from_string_validated(
            "/leanconsensus/0x12345678/block/ssz_snappy",
            expected_fork_digest="0x12345678",
        ) == GossipTopic(kind=TopicKind.BLOCK, fork_digest="0x12345678")

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
        assert topic == GossipTopic(kind=TopicKind.BLOCK, fork_digest="0x12345678")
        assert str(topic) == "/leanconsensus/0x12345678/block/ssz_snappy"

    def test_gossip_topic_from_string(self) -> None:
        """Test parsing topic string."""
        topic_str = "/leanconsensus/0x12345678/block/ssz_snappy"
        assert GossipTopic.from_string(topic_str) == GossipTopic(
            kind=TopicKind.BLOCK, fork_digest="0x12345678"
        )

    def test_gossip_topic_factory_methods(self) -> None:
        """Test GossipTopic factory methods."""
        assert GossipTopic.block("0xabcd1234") == GossipTopic(
            kind=TopicKind.BLOCK, fork_digest="0xabcd1234"
        )
        assert GossipTopic.attestation_subnet("0xabcd1234", SubnetId(0)) == GossipTopic(
            kind=TopicKind.ATTESTATION_SUBNET, fork_digest="0xabcd1234", subnet_id=SubnetId(0)
        )

    def test_parse_topic_string(self) -> None:
        """Test topic string parsing."""
        assert parse_topic_string("/leanconsensus/0x12345678/block/ssz_snappy") == (
            "leanconsensus",
            "0x12345678",
            "block",
            "ssz_snappy",
        )

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
        assert mesh.params == GossipsubParameters(d=8, d_low=6, d_high=12, d_lazy=6)

    def test_subscribe_and_unsubscribe(self) -> None:
        """Test topic subscription."""
        mesh = MeshState(params=GossipsubParameters())

        mesh.subscribe(TopicId("topic1"))
        assert TopicId("topic1") in mesh.subscriptions
        assert TopicId("topic2") not in mesh.subscriptions

        peers = mesh.unsubscribe(TopicId("topic1"))
        assert TopicId("topic1") not in mesh.subscriptions
        assert peers == set()

    def test_add_remove_mesh_peers(self) -> None:
        """Test adding and removing peers from mesh."""
        mesh = MeshState(params=GossipsubParameters())
        mesh.subscribe(TopicId("topic1"))

        peer1 = peer("peer1")
        peer2 = peer("peer2")

        assert mesh.add_to_mesh(TopicId("topic1"), peer1)
        assert mesh.add_to_mesh(TopicId("topic1"), peer2)
        assert not mesh.add_to_mesh(TopicId("topic1"), peer1)  # Already in mesh

        assert mesh.get_mesh_peers(TopicId("topic1")) == {peer1, peer2}

        assert mesh.remove_from_mesh(TopicId("topic1"), peer1)
        assert not mesh.remove_from_mesh(TopicId("topic1"), peer1)  # Already removed

        assert mesh.get_mesh_peers(TopicId("topic1")) == {peer2}

    def test_gossip_peer_selection(self) -> None:
        """Test selection of non-mesh peers for gossip."""
        params = GossipsubParameters(d_lazy=3)
        mesh = MeshState(params=params)
        mesh.subscribe(TopicId("topic1"))
        peer1 = peer("peer1")
        peer2 = peer("peer2")
        mesh.add_to_mesh(TopicId("topic1"), peer1)
        mesh.add_to_mesh(TopicId("topic1"), peer2)

        # Exactly d_lazy=3 non-mesh peers → all returned deterministically.
        non_mesh = {peer("peer3"), peer("peer4"), peer("peer5")}
        all_peers = {peer1, peer2} | non_mesh

        gossip_peers = mesh.select_peers_for_gossip(TopicId("topic1"), all_peers)

        assert set(gossip_peers) == non_mesh


class TestTopicMesh:
    """Test suite for TopicMesh dataclass."""

    def test_topic_mesh_add_remove(self) -> None:
        """Test adding and removing peers."""
        topic_mesh = TopicMesh()
        peer1 = peer("peer1")

        assert topic_mesh.add_peer(peer1)
        assert not topic_mesh.add_peer(peer1)  # Already exists
        assert topic_mesh.peers == {peer1}

        assert topic_mesh.remove_peer(peer1)
        assert not topic_mesh.remove_peer(peer1)  # Already removed
        assert topic_mesh.peers == set()


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
        topic = TopicId("fanout_topic")

        available = {peer("p1"), peer("p2"), peer("p3"), peer("p4")}
        result = mesh.update_fanout(topic, available)

        assert len(result) <= 3  # Up to D peers
        assert len(result) > 0

    def test_update_fanout_returns_mesh_if_subscribed(self) -> None:
        """update_fanout returns mesh peers for subscribed topics."""
        mesh = MeshState(params=GossipsubParameters(d=3))
        topic = TopicId("sub_topic")

        mesh.subscribe(topic)
        p1 = peer("p1")
        mesh.add_to_mesh(topic, p1)

        result = mesh.update_fanout(topic, {p1, peer("p2")})
        assert result == {p1}

    def test_update_fanout_fills_to_d(self) -> None:
        """update_fanout fills fanout up to D peers."""
        mesh = MeshState(params=GossipsubParameters(d=4))
        topic = TopicId("fanout_topic")

        names = ["pA", "pB", "pC", "pD", "pE", "pF", "pG", "pH", "pJ", "pK"]
        available = {peer(n) for n in names}
        result = mesh.update_fanout(topic, available)

        assert len(result) == 4

    def test_cleanup_fanouts_removes_stale(self) -> None:
        """cleanup_fanouts removes stale entries."""
        mesh = MeshState(params=GossipsubParameters())
        topic = TopicId("old_topic")

        mesh.update_fanout(topic, {peer("p1")})
        # Make it stale
        mesh._fanouts[topic].last_published = 0.0

        removed = mesh.cleanup_fanouts(ttl=60.0)
        assert removed == 1
        assert topic not in mesh._fanouts

    def test_cleanup_fanouts_keeps_fresh(self) -> None:
        """cleanup_fanouts keeps recent entries."""
        mesh = MeshState(params=GossipsubParameters())
        topic = TopicId("fresh_topic")

        mesh.update_fanout(topic, {peer("p1")})
        # last_published is set to time.time() by update_fanout

        removed = mesh.cleanup_fanouts(ttl=60.0)
        assert removed == 0
        assert topic in mesh._fanouts

    def test_subscribe_promotes_fanout_to_mesh(self) -> None:
        """Subscribing to a topic promotes fanout peers to mesh."""
        mesh = MeshState(params=GossipsubParameters())
        topic = TopicId("promote_topic")

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
        topic = TopicId("unsub_topic")

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
        mesh.subscribe(TopicId("topic"))

        names = ["gA", "gB", "gC", "gD", "gE", "gF", "gG", "gH", "gJ", "gK"]
        all_peers = {peer(n) for n in names}
        result = mesh.select_peers_for_gossip(TopicId("topic"), all_peers)

        assert len(result) <= 2

    def test_select_peers_for_gossip_excludes_mesh(self) -> None:
        """Gossip peer selection excludes mesh peers."""
        params = GossipsubParameters(d_lazy=5)
        mesh = MeshState(params=params)
        mesh.subscribe(TopicId("topic"))

        mesh_peer = peer("mesh1")
        mesh.add_to_mesh(TopicId("topic"), mesh_peer)

        all_peers = {mesh_peer, peer("p1"), peer("p2")}
        result = mesh.select_peers_for_gossip(TopicId("topic"), all_peers)

        assert mesh_peer not in result


class TestRPCProtobufEncoding:
    """Test suite for GossipSub RPC protobuf wire format encoding/decoding.

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
        msg = Message(
            from_peer=b"peer123",
            data=b"hello world",
            seqno=b"\x00\x01\x02\x03\x04\x05\x06\x07",
            topic=TopicId("/test/topic"),
            signature=b"sig" * 16,
            key=b"pubkey",
        )
        assert Message.decode(msg.encode()) == msg

    def test_message_minimal(self) -> None:
        """Test Message with only required fields."""
        msg = Message(topic=TopicId("/test/topic"), data=b"payload")
        assert Message.decode(msg.encode()) == msg

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

    def test_rpc_empty_check(self) -> None:
        """Test RPC is_empty method."""
        empty_rpc = RPC()
        assert empty_rpc.is_empty()

        non_empty = RPC(subscriptions=[SubOpts(subscribe=True, topic_id=TopicId("/topic"))])
        assert not non_empty.is_empty()

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
        """Test wire format matches expected protobuf encoding.

        Verifies that our encoding produces bytes that round-trip
        correctly through decode, matching the original structure.
        """
        rpc = RPC(subscriptions=[SubOpts(subscribe=True, topic_id=TopicId("test"))])
        assert RPC.decode(rpc.encode()) == rpc

    def test_large_message_encoding(self) -> None:
        """Test encoding of large messages (typical block size)."""
        rpc = RPC(publish=[Message(topic=TopicId("/blocks"), data=b"x" * 100_000)])
        assert RPC.decode(rpc.encode()) == rpc


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
        assert handler.get_topic("/leanconsensus/0x12345678/block/ssz_snappy") == GossipTopic(
            kind=TopicKind.BLOCK, fork_digest="0x12345678"
        )
