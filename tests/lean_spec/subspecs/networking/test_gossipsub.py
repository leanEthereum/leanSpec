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

        attestation_topic = GossipTopic.attestation("0xabcd1234")
        assert attestation_topic.kind == TopicKind.ATTESTATION

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
        assert TopicKind.ATTESTATION.value == "attestation"
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
