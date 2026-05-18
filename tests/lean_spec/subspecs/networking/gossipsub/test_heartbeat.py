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
from lean_spec.subspecs.networking.gossipsub.rpc import (
    RPC,
    ControlGraft,
    ControlIHave,
    ControlMessage,
    ControlPrune,
)
from lean_spec.subspecs.networking.gossipsub.types import MessageId, Timestamp, TopicId

from .conftest import add_peer, make_behavior, make_peer


class TestMaintainMesh:
    """Tests for mesh size maintenance."""

    @pytest.mark.asyncio
    async def test_grafts_when_below_d_low(self) -> None:
        """GRAFT peers when mesh is below d_low."""
        behavior, capture = make_behavior(d=4, d_low=3, d_high=6)
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        # Exactly d=4 eligible peers so random.sample selects all deterministically.
        names = ["peerA", "peerB", "peerC", "peerD"]
        for name in names:
            add_peer(behavior, name, {topic})

        now = time.time()
        await behavior._maintain_mesh(topic, now)

        expected_peers = {make_peer(name) for name in names}
        graft_rpc = RPC(control=ControlMessage(graft=[ControlGraft(topic_id=topic)]))
        assert {p for p, _ in capture.sent} == expected_peers
        assert all(rpc == graft_rpc for _, rpc in capture.sent)
        assert behavior.mesh.get_mesh_peers(topic) == expected_peers

    @pytest.mark.asyncio
    async def test_prunes_when_above_d_high(self) -> None:
        """PRUNE excess peers when mesh exceeds d_high."""
        behavior, capture = make_behavior(d=3, d_low=2, d_high=4)
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        # Add 6 peers and put them all in mesh (exceeds d_high=4)
        names = ["peerA", "peerB", "peerC", "peerD", "peerE", "peerF"]
        all_peers = set()
        for name in names:
            pid = add_peer(behavior, name, {topic})
            behavior.mesh.add_to_mesh(topic, pid)
            all_peers.add(pid)

        now = time.time()
        await behavior._maintain_mesh(topic, now)

        mesh = behavior.mesh.get_mesh_peers(topic)
        assert len(mesh) == 3

        prune_rpc = RPC(
            control=ControlMessage(prune=[ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)])
        )
        pruned_peers = {p for p, _ in capture.sent}
        assert len(capture.sent) == 3
        assert all(rpc == prune_rpc for _, rpc in capture.sent)
        assert pruned_peers | mesh == all_peers

    @pytest.mark.asyncio
    async def test_respects_backoff(self) -> None:
        """Mesh maintenance does not GRAFT peers in backoff."""
        behavior, capture = make_behavior(d=4, d_low=3, d_high=6)
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        # Add peer with backoff set
        pid = add_peer(behavior, "peerA", {topic})
        behavior._peers[pid].backoff[topic] = time.time() + 999

        # Add another peer without backoff
        pid2 = add_peer(behavior, "peerB", {topic})

        now = time.time()
        await behavior._maintain_mesh(topic, now)

        # Only the non-backoff peer should be in mesh
        mesh = behavior.mesh.get_mesh_peers(topic)
        assert pid not in mesh
        assert pid2 in mesh

    @pytest.mark.asyncio
    async def test_skips_peers_without_outbound_stream(self) -> None:
        """Mesh maintenance skips peers without outbound streams."""
        behavior, capture = make_behavior(d=4, d_low=3, d_high=6)
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        # Add peer without outbound stream
        add_peer(behavior, "noStrm", {topic}, with_stream=False)
        # Add peer with outbound stream
        pid_ok = add_peer(behavior, "hasStrm", {topic}, with_stream=True)

        now = time.time()
        await behavior._maintain_mesh(topic, now)

        mesh = behavior.mesh.get_mesh_peers(topic)
        assert make_peer("noStrm") not in mesh
        assert pid_ok in mesh

    @pytest.mark.asyncio
    async def test_noop_when_within_bounds(self) -> None:
        """No GRAFT or PRUNE when mesh is within [d_low, d_high]."""
        behavior, capture = make_behavior(d=4, d_low=3, d_high=6)
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        # Put exactly 4 peers in mesh (== d, within [d_low=3, d_high=6])
        names = ["peerA", "peerB", "peerC", "peerD"]
        for name in names:
            pid = add_peer(behavior, name, {topic})
            behavior.mesh.add_to_mesh(topic, pid)

        now = time.time()
        await behavior._maintain_mesh(topic, now)

        assert capture.sent == []
        assert len(behavior.mesh.get_mesh_peers(topic)) == 4

    @pytest.mark.asyncio
    async def test_prune_sets_bidirectional_backoff(self) -> None:
        """When we PRUNE peers, we also set our own backoff for them."""
        behavior, capture = make_behavior(d=2, d_low=1, d_high=3)
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        # Add 5 peers in mesh (> d_high=3)
        peers = []
        names = ["peerA", "peerB", "peerC", "peerD", "peerE"]
        for name in names:
            pid = add_peer(behavior, name, {topic})
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


class TestEmitGossip:
    """Tests for IHAVE gossip emission."""

    @pytest.mark.asyncio
    async def test_sends_ihave_to_non_mesh_peers(self) -> None:
        """IHAVE is sent to non-mesh peers that are subscribed."""
        behavior, capture = make_behavior(d=2, d_low=1, d_high=4, d_lazy=2)
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        # Add message to cache
        msg = GossipsubMessage(topic=topic.encode("utf-8"), raw_data=b"data")
        behavior.message_cache.put(topic, msg)

        # Add mesh peer and non-mesh peer
        mesh_pid = add_peer(behavior, "meshPx", {topic})
        behavior.mesh.add_to_mesh(topic, mesh_pid)
        non_mesh_pid = add_peer(behavior, "nonMeshPx", {topic})

        await behavior._emit_gossip(topic)

        assert capture.sent == [
            (
                non_mesh_pid,
                RPC(
                    control=ControlMessage(
                        ihave=[ControlIHave(topic_id=topic, message_ids=[msg.id])]
                    )
                ),
            )
        ]

    @pytest.mark.asyncio
    async def test_skips_when_no_cached_messages(self) -> None:
        """No IHAVE sent when cache is empty."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        add_peer(behavior, "peer1", {topic})

        await behavior._emit_gossip(topic)

        assert capture.sent == []

    @pytest.mark.asyncio
    async def test_skips_peers_without_outbound_stream(self) -> None:
        """Gossip skips peers without outbound streams."""
        behavior, capture = make_behavior(d_lazy=2)
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        msg = GossipsubMessage(topic=topic.encode("utf-8"), raw_data=b"data")
        behavior.message_cache.put(topic, msg)

        # Only add peer without stream (no mesh peers either)
        add_peer(behavior, "noStrm", {topic}, with_stream=False)

        await behavior._emit_gossip(topic)

        assert capture.sent == []


class TestHeartbeatIntegration:
    """Tests for the complete heartbeat cycle."""

    @pytest.mark.asyncio
    async def test_shifts_message_cache(self) -> None:
        """Heartbeat shifts the message cache window."""
        behavior, _ = make_behavior()

        msg = GossipsubMessage(topic=b"topic", raw_data=b"data")
        behavior.message_cache.put(TopicId("topic"), msg)

        assert behavior.message_cache.has(msg.id)

        # Run heartbeat several times to shift through all windows
        for _ in range(7):
            await behavior._heartbeat()

        # After enough shifts, old messages should be evicted
        assert not behavior.message_cache.has(msg.id)

    @pytest.mark.asyncio
    async def test_cleans_seen_cache(self) -> None:
        """Heartbeat cleans expired entries from seen cache."""
        behavior, _ = make_behavior()
        behavior.seen_cache = SeenCache(ttl_seconds=1)

        msg_id = MessageId(b"12345678901234567890")
        behavior.seen_cache.add(msg_id, Timestamp(time.time() - 10))  # Already expired

        await behavior._heartbeat()

        assert not behavior.seen_cache.has(msg_id)

    @pytest.mark.asyncio
    async def test_iterates_all_subscribed_topics(self) -> None:
        """Heartbeat processes all subscribed topics."""
        behavior, capture = make_behavior(d=2, d_low=1, d_high=4)

        topic1 = TopicId("topic1")
        topic2 = TopicId("topic2")
        behavior.subscribe(topic1)
        behavior.subscribe(topic2)

        # Add peers for both topics
        add_peer(behavior, "peer1", {topic1, topic2})
        add_peer(behavior, "peer2", {topic1, topic2})
        add_peer(behavior, "peer3", {topic1, topic2})

        await behavior._heartbeat()

        # Both topics should have been grafted (mesh was empty for both)
        mesh1 = behavior.mesh.get_mesh_peers(topic1)
        mesh2 = behavior.mesh.get_mesh_peers(topic2)
        assert len(mesh1) == 2  # d=2, 3 available
        assert len(mesh2) == 2

    @pytest.mark.asyncio
    async def test_cleans_fanout_entries(self) -> None:
        """Heartbeat removes stale fanout entries."""
        behavior, _ = make_behavior()

        # Create a stale fanout entry by publishing to an unsubscribed topic
        # Then manually make it stale
        topic = TopicId("unsubscribed_topic")
        available = {add_peer(behavior, "peer1", {topic})}
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
        behavior, _ = make_behavior()
        pid = add_peer(behavior, "peer1")
        behavior._peers[pid].dont_want_ids.add(MessageId(b"12345678901234567890"))

        assert len(behavior._peers[pid].dont_want_ids) == 1

        await behavior._heartbeat()

        assert len(behavior._peers[pid].dont_want_ids) == 0

    @pytest.mark.asyncio
    async def test_gossip_includes_fanout_topics(self) -> None:
        """Heartbeat emits gossip for fanout topics, not just subscribed ones."""
        behavior, capture = make_behavior(d_lazy=2)

        # Subscribe to one topic
        sub_topic = TopicId("subscribed_topic")
        behavior.subscribe(sub_topic)

        # Create a fanout entry for an unsubscribed topic with cached messages
        fan_topic = TopicId("fanout_topic")
        fan_peer = add_peer(behavior, "fanPeer", {fan_topic})
        behavior.mesh.update_fanout(fan_topic, {fan_peer})

        # Add a message to cache for the fanout topic
        msg = GossipsubMessage(topic=fan_topic.encode("utf-8"), raw_data=b"data")
        behavior.message_cache.put(fan_topic, msg)

        await behavior._heartbeat()

        # Heartbeat emits gossip for fanout topics.
        # Filter to IHAVE RPCs for the fanout topic.
        fanout_ihaves = [
            (p, r)
            for p, r in capture.sent
            if r.control and any(ih.topic_id == fan_topic for ih in r.control.ihave)
        ]
        assert fanout_ihaves == [
            (
                fan_peer,
                RPC(
                    control=ControlMessage(
                        ihave=[ControlIHave(topic_id=fan_topic, message_ids=[msg.id])]
                    )
                ),
            )
        ]
