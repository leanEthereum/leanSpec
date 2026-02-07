"""Tests for gossipsub heartbeat and mesh maintenance.

Tests cover mesh maintenance (GRAFT/PRUNE), gossip emission (IHAVE),
fanout cleanup, cache aging, and IDONTWANT cleanup.
"""

from __future__ import annotations

import time

import pytest

from lean_spec.subspecs.networking.config import PRUNE_BACKOFF
from lean_spec.subspecs.networking.gossipsub.mcache import SeenCache
from lean_spec.subspecs.networking.gossipsub.message import GossipsubMessage
from lean_spec.types import Bytes20

from .conftest import _add_peer, _make_behavior, _peer

# =============================================================================
# Mesh Maintenance
# =============================================================================


class TestMaintainMesh:
    """Tests for mesh size maintenance."""

    @pytest.mark.asyncio
    async def test_grafts_when_below_d_low(self) -> None:
        """GRAFT peers when mesh is below d_low."""
        behavior, capture = _make_behavior(d=4, d_low=3, d_high=6)
        topic = "test_topic"
        behavior.subscribe(topic)

        # Add 5 eligible peers (subscribed, with outbound stream)
        names = ["peerA", "peerB", "peerC", "peerD", "peerE"]
        for name in names:
            _add_peer(behavior, name, {topic})

        # Mesh is empty (0 < d_low=3), should graft up to d=4
        now = time.time()
        await behavior._maintain_mesh(topic, now)

        # Verify GRAFTs were sent
        graft_rpcs = [(p, r) for p, r in capture.sent if r.control and r.control.graft]
        assert len(graft_rpcs) == 4  # d=4 peers grafted
        # All grafted peers should be in mesh
        mesh = behavior.mesh.get_mesh_peers(topic)
        assert len(mesh) == 4

    @pytest.mark.asyncio
    async def test_prunes_when_above_d_high(self) -> None:
        """PRUNE excess peers when mesh exceeds d_high."""
        behavior, capture = _make_behavior(d=3, d_low=2, d_high=4)
        topic = "test_topic"
        behavior.subscribe(topic)

        # Add 6 peers and put them all in mesh (exceeds d_high=4)
        names = ["peerA", "peerB", "peerC", "peerD", "peerE", "peerF"]
        for name in names:
            pid = _add_peer(behavior, name, {topic})
            behavior.mesh.add_to_mesh(topic, pid)

        now = time.time()
        await behavior._maintain_mesh(topic, now)

        # Mesh should be reduced to d=3
        mesh = behavior.mesh.get_mesh_peers(topic)
        assert len(mesh) == 3

        # Pruned peers should have received PRUNE
        prune_rpcs = [(p, r) for p, r in capture.sent if r.control and r.control.prune]
        assert len(prune_rpcs) == 3  # 6 - 3 = 3 pruned

    @pytest.mark.asyncio
    async def test_respects_backoff(self) -> None:
        """Mesh maintenance does not GRAFT peers in backoff."""
        behavior, capture = _make_behavior(d=4, d_low=3, d_high=6)
        topic = "test_topic"
        behavior.subscribe(topic)

        # Add peer with backoff set
        pid = _add_peer(behavior, "peerA", {topic})
        behavior._peers[pid].backoff[topic] = time.time() + 999

        # Add another peer without backoff
        pid2 = _add_peer(behavior, "peerB", {topic})

        now = time.time()
        await behavior._maintain_mesh(topic, now)

        # Only the non-backoff peer should be in mesh
        mesh = behavior.mesh.get_mesh_peers(topic)
        assert pid not in mesh
        assert pid2 in mesh

    @pytest.mark.asyncio
    async def test_skips_peers_without_outbound_stream(self) -> None:
        """Mesh maintenance skips peers without outbound streams."""
        behavior, capture = _make_behavior(d=4, d_low=3, d_high=6)
        topic = "test_topic"
        behavior.subscribe(topic)

        # Add peer without outbound stream
        _add_peer(behavior, "noStrm", {topic}, with_stream=False)
        # Add peer with outbound stream
        pid_ok = _add_peer(behavior, "hasStrm", {topic}, with_stream=True)

        now = time.time()
        await behavior._maintain_mesh(topic, now)

        mesh = behavior.mesh.get_mesh_peers(topic)
        assert _peer("noStrm") not in mesh
        assert pid_ok in mesh

    @pytest.mark.asyncio
    async def test_noop_when_within_bounds(self) -> None:
        """No GRAFT or PRUNE when mesh is within [d_low, d_high]."""
        behavior, capture = _make_behavior(d=4, d_low=3, d_high=6)
        topic = "test_topic"
        behavior.subscribe(topic)

        # Put exactly 4 peers in mesh (== d, within [d_low=3, d_high=6])
        names = ["peerA", "peerB", "peerC", "peerD"]
        for name in names:
            pid = _add_peer(behavior, name, {topic})
            behavior.mesh.add_to_mesh(topic, pid)

        now = time.time()
        await behavior._maintain_mesh(topic, now)

        # No GRAFTs or PRUNEs sent
        assert len(capture.sent) == 0
        assert len(behavior.mesh.get_mesh_peers(topic)) == 4

    @pytest.mark.asyncio
    async def test_prune_sets_bidirectional_backoff(self) -> None:
        """When we PRUNE peers, we also set our own backoff for them."""
        behavior, capture = _make_behavior(d=2, d_low=1, d_high=3)
        topic = "test_topic"
        behavior.subscribe(topic)

        # Add 5 peers in mesh (> d_high=3)
        peers = []
        names = ["peerA", "peerB", "peerC", "peerD", "peerE"]
        for name in names:
            pid = _add_peer(behavior, name, {topic})
            behavior.mesh.add_to_mesh(topic, pid)
            peers.append(pid)

        now = time.time()
        await behavior._maintain_mesh(topic, now)

        # Check that pruned peers have backoff set on our side
        mesh = behavior.mesh.get_mesh_peers(topic)
        for pid in peers:
            if pid not in mesh:
                state = behavior._peers[pid]
                assert topic in state.backoff
                assert state.backoff[topic] >= now + PRUNE_BACKOFF


# =============================================================================
# Gossip Emission
# =============================================================================


class TestEmitGossip:
    """Tests for IHAVE gossip emission."""

    @pytest.mark.asyncio
    async def test_sends_ihave_to_non_mesh_peers(self) -> None:
        """IHAVE is sent to non-mesh peers that are subscribed."""
        behavior, capture = _make_behavior(d=2, d_low=1, d_high=4, d_lazy=2)
        topic = "test_topic"
        behavior.subscribe(topic)

        # Add message to cache
        msg = GossipsubMessage(topic=topic.encode("utf-8"), raw_data=b"data")
        behavior.message_cache.put(topic, msg)

        # Add mesh peer and non-mesh peer
        mesh_pid = _add_peer(behavior, "meshPx", {topic})
        behavior.mesh.add_to_mesh(topic, mesh_pid)
        non_mesh_pid = _add_peer(behavior, "nonMeshPx", {topic})

        await behavior._emit_gossip(topic)

        # IHAVE should go to non-mesh peer
        ihave_rpcs = [(p, r) for p, r in capture.sent if r.control and r.control.ihave]
        assert len(ihave_rpcs) >= 1
        sent_to = {p for p, _ in ihave_rpcs}
        assert non_mesh_pid in sent_to
        assert mesh_pid not in sent_to

    @pytest.mark.asyncio
    async def test_skips_when_no_cached_messages(self) -> None:
        """No IHAVE sent when cache is empty."""
        behavior, capture = _make_behavior()
        topic = "test_topic"
        behavior.subscribe(topic)

        _add_peer(behavior, "peer1", {topic})

        await behavior._emit_gossip(topic)

        assert len(capture.sent) == 0

    @pytest.mark.asyncio
    async def test_skips_peers_without_outbound_stream(self) -> None:
        """Gossip skips peers without outbound streams."""
        behavior, capture = _make_behavior(d_lazy=2)
        topic = "test_topic"
        behavior.subscribe(topic)

        msg = GossipsubMessage(topic=topic.encode("utf-8"), raw_data=b"data")
        behavior.message_cache.put(topic, msg)

        # Only add peer without stream (no mesh peers either)
        _add_peer(behavior, "noStrm", {topic}, with_stream=False)

        await behavior._emit_gossip(topic)

        assert len(capture.sent) == 0


# =============================================================================
# Full Heartbeat Integration
# =============================================================================


class TestHeartbeatIntegration:
    """Tests for the complete heartbeat cycle."""

    @pytest.mark.asyncio
    async def test_shifts_message_cache(self) -> None:
        """Heartbeat shifts the message cache window."""
        behavior, _ = _make_behavior()

        msg = GossipsubMessage(topic=b"topic", raw_data=b"data")
        behavior.message_cache.put("topic", msg)

        initial_len = len(behavior.message_cache)
        assert initial_len == 1

        # Run heartbeat several times to shift through all windows
        for _ in range(7):
            await behavior._heartbeat()

        # After enough shifts, old messages should be evicted
        assert len(behavior.message_cache) == 0

    @pytest.mark.asyncio
    async def test_cleans_seen_cache(self) -> None:
        """Heartbeat cleans expired entries from seen cache."""
        behavior, _ = _make_behavior()
        behavior.seen_cache = SeenCache(ttl_seconds=1)

        msg_id = Bytes20(b"12345678901234567890")
        behavior.seen_cache.add(msg_id, time.time() - 10)  # Already expired

        await behavior._heartbeat()

        assert not behavior.seen_cache.has(msg_id)

    @pytest.mark.asyncio
    async def test_iterates_all_subscribed_topics(self) -> None:
        """Heartbeat processes all subscribed topics."""
        behavior, capture = _make_behavior(d=2, d_low=1, d_high=4)

        topic1 = "topic1"
        topic2 = "topic2"
        behavior.subscribe(topic1)
        behavior.subscribe(topic2)

        # Add peers for both topics
        _add_peer(behavior, "peer1", {topic1, topic2})
        _add_peer(behavior, "peer2", {topic1, topic2})
        _add_peer(behavior, "peer3", {topic1, topic2})

        await behavior._heartbeat()

        # Both topics should have been grafted (mesh was empty for both)
        mesh1 = behavior.mesh.get_mesh_peers(topic1)
        mesh2 = behavior.mesh.get_mesh_peers(topic2)
        assert len(mesh1) == 2  # d=2, 3 available
        assert len(mesh2) == 2

    @pytest.mark.asyncio
    async def test_cleans_fanout_entries(self) -> None:
        """Heartbeat removes stale fanout entries."""
        behavior, _ = _make_behavior()

        # Create a stale fanout entry by publishing to an unsubscribed topic
        # Then manually make it stale
        topic = "unsubscribed_topic"
        available = {_add_peer(behavior, "peer1", {topic})}
        behavior.mesh.update_fanout(topic, available)

        # Make the fanout entry stale
        fanout = behavior.mesh._fanouts[topic]
        fanout.last_published = time.time() - 9999

        await behavior._heartbeat()

        # Stale fanout should be cleaned up
        assert topic not in behavior.mesh._fanouts

    @pytest.mark.asyncio
    async def test_clears_idontwant_sets(self) -> None:
        """Heartbeat clears per-peer IDONTWANT sets."""
        behavior, _ = _make_behavior()
        pid = _add_peer(behavior, "peer1")
        behavior._peers[pid].dont_want_ids.add(Bytes20(b"12345678901234567890"))

        assert len(behavior._peers[pid].dont_want_ids) == 1

        await behavior._heartbeat()

        assert len(behavior._peers[pid].dont_want_ids) == 0

    @pytest.mark.asyncio
    async def test_gossip_includes_fanout_topics(self) -> None:
        """Heartbeat emits gossip for fanout topics, not just subscribed ones."""
        behavior, capture = _make_behavior(d_lazy=2)

        # Subscribe to one topic
        sub_topic = "subscribed_topic"
        behavior.subscribe(sub_topic)

        # Create a fanout entry for an unsubscribed topic with cached messages
        fan_topic = "fanout_topic"
        fan_peer = _add_peer(behavior, "fanPeer", {fan_topic})
        behavior.mesh.update_fanout(fan_topic, {fan_peer})

        # Add a message to cache for the fanout topic
        msg = GossipsubMessage(topic=fan_topic.encode("utf-8"), raw_data=b"data")
        behavior.message_cache.put(fan_topic, msg)

        await behavior._heartbeat()

        # IHAVE should have been sent for the fanout topic
        ihave_rpcs = [(p, r) for p, r in capture.sent if r.control and r.control.ihave]
        fanout_ihaves = [
            (p, r)
            for p, r in ihave_rpcs
            if r.control and any(ih.topic_id == fan_topic for ih in r.control.ihave)
        ]
        assert len(fanout_ihaves) >= 1
