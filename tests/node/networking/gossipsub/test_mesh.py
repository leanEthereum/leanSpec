"""Tests for gossipsub mesh state management."""

from lean_spec.node.networking import PeerId
from lean_spec.node.networking.gossipsub import GossipsubParameters
from lean_spec.node.networking.gossipsub.mesh import FanoutEntry, MeshState, TopicMesh
from lean_spec.node.networking.gossipsub.types import TopicId


def peer(name: str) -> PeerId:
    """Create a PeerId from a test name."""
    return PeerId.from_base58(name)


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
        fanout_entry = FanoutEntry()
        fanout_entry.last_published = 1000.0

        assert not fanout_entry.is_stale(current_time=1050.0, ttl=60.0)
        assert fanout_entry.is_stale(current_time=1070.0, ttl=60.0)


class TestFanoutOperations:
    """Tests for fanout management in MeshState."""

    def test_update_fanout_creates_entry(self) -> None:
        """update_fanout creates a new fanout entry if none exists."""
        mesh = MeshState(params=GossipsubParameters(d=3))
        topic = TopicId("fanout_topic")

        available = {peer("p1"), peer("p2"), peer("p3"), peer("p4")}
        fanout_peers = mesh.update_fanout(topic, available)

        assert len(fanout_peers) <= 3  # Up to D peers
        assert len(fanout_peers) > 0

    def test_update_fanout_returns_mesh_if_subscribed(self) -> None:
        """update_fanout returns mesh peers for subscribed topics."""
        mesh = MeshState(params=GossipsubParameters(d=3))
        topic = TopicId("sub_topic")

        mesh.subscribe(topic)
        p1 = peer("p1")
        mesh.add_to_mesh(topic, p1)

        fanout_peers = mesh.update_fanout(topic, {p1, peer("p2")})
        assert fanout_peers == {p1}

    def test_update_fanout_fills_to_d(self) -> None:
        """update_fanout fills fanout up to D peers."""
        mesh = MeshState(params=GossipsubParameters(d=4))
        topic = TopicId("fanout_topic")

        names = ["pA", "pB", "pC", "pD", "pE", "pF", "pG", "pH", "pJ", "pK"]
        available = {peer(name) for name in names}
        fanout_peers = mesh.update_fanout(topic, available)

        assert len(fanout_peers) == 4

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

        pruned_mesh_peers = mesh.unsubscribe(topic)
        assert pruned_mesh_peers == {p1, p2}

    def test_select_peers_for_gossip_respects_d_lazy(self) -> None:
        """Gossip peer selection returns at most d_lazy peers."""
        params = GossipsubParameters(d_lazy=2)
        mesh = MeshState(params=params)
        mesh.subscribe(TopicId("topic"))

        names = ["gA", "gB", "gC", "gD", "gE", "gF", "gG", "gH", "gJ", "gK"]
        all_peers = {peer(name) for name in names}
        gossip_peers = mesh.select_peers_for_gossip(TopicId("topic"), all_peers)

        assert len(gossip_peers) <= 2

    def test_select_peers_for_gossip_excludes_mesh(self) -> None:
        """Gossip peer selection excludes mesh peers."""
        params = GossipsubParameters(d_lazy=5)
        mesh = MeshState(params=params)
        mesh.subscribe(TopicId("topic"))

        mesh_peer = peer("mesh1")
        mesh.add_to_mesh(TopicId("topic"), mesh_peer)

        all_peers = {mesh_peer, peer("p1"), peer("p2")}
        gossip_peers = mesh.select_peers_for_gossip(TopicId("topic"), all_peers)

        assert mesh_peer not in gossip_peers
