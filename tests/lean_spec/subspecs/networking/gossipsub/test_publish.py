"""Tests for gossipsub publish and broadcast subscription.

Tests cover the publish() method, fanout publishing, deduplication,
and subscription broadcast with GRAFT/PRUNE coordination.
"""

from __future__ import annotations

import pytest

from lean_spec.subspecs.networking.gossipsub.message import GossipsubMessage

from .conftest import _add_peer, _make_behavior

# =============================================================================
# Publish
# =============================================================================


class TestPublish:
    """Tests for the publish() method."""

    @pytest.mark.asyncio
    async def test_publish_to_subscribed_topic(self) -> None:
        """Published message reaches mesh peers for a subscribed topic."""
        behavior, capture = _make_behavior(d=3, d_low=2, d_high=6)
        topic = "testTopic"
        behavior.subscribe(topic)

        p1 = _add_peer(behavior, "peerA", {topic})
        p2 = _add_peer(behavior, "peerB", {topic})
        behavior.mesh.add_to_mesh(topic, p1)
        behavior.mesh.add_to_mesh(topic, p2)

        await behavior.publish(topic, b"hello")

        sent_peers = [p for p, _ in capture.sent]
        assert p1 in sent_peers
        assert p2 in sent_peers

    @pytest.mark.asyncio
    async def test_publish_to_unsubscribed_topic_uses_fanout(self) -> None:
        """Publishing to an unsubscribed topic uses fanout peers."""
        behavior, capture = _make_behavior(d=2, d_low=1, d_high=4)

        topic = "fanoutTopic"
        _add_peer(behavior, "peerA", {topic})
        _add_peer(behavior, "peerB", {topic})

        await behavior.publish(topic, b"fanoutMsg")

        # At least one peer should have received the message.
        sent_peers = [p for p, _ in capture.sent]
        assert len(sent_peers) > 0
        # The topic should now have a fanout entry.
        assert topic in behavior.mesh.fanout_topics

    @pytest.mark.asyncio
    async def test_publish_duplicate_skipped(self) -> None:
        """Publishing the same message twice is a no-op the second time."""
        behavior, capture = _make_behavior()
        topic = "testTopic"
        behavior.subscribe(topic)

        p1 = _add_peer(behavior, "peerA", {topic})
        behavior.mesh.add_to_mesh(topic, p1)

        await behavior.publish(topic, b"payload")
        first_count = len(capture.sent)

        await behavior.publish(topic, b"payload")
        assert len(capture.sent) == first_count

    @pytest.mark.asyncio
    async def test_publish_caches_message(self) -> None:
        """Published messages are added to the message cache."""
        behavior, _ = _make_behavior()
        topic = "testTopic"
        behavior.subscribe(topic)

        await behavior.publish(topic, b"cacheMe")

        msg_id = GossipsubMessage.compute_id(topic.encode("utf-8"), b"cacheMe")
        assert behavior.seen_cache.has(msg_id)
        assert behavior.message_cache.has(msg_id)

    @pytest.mark.asyncio
    async def test_publish_empty_mesh_no_crash(self) -> None:
        """Publishing to an empty mesh does not crash."""
        behavior, capture = _make_behavior()
        topic = "emptyTopic"
        behavior.subscribe(topic)

        # No peers added -- mesh is empty.
        await behavior.publish(topic, b"data")

        assert len(capture.sent) == 0


# =============================================================================
# Broadcast Subscription
# =============================================================================


class TestBroadcastSubscription:
    """Tests for _broadcast_subscription (via subscribe/unsubscribe)."""

    @pytest.mark.asyncio
    async def test_subscribe_sends_subscription_to_all_peers(self) -> None:
        """Subscribing broadcasts a subscription RPC to all peers."""
        behavior, capture = _make_behavior(d=2, d_low=1, d_high=4)
        behavior._running = True

        p1 = _add_peer(behavior, "peerA", set())
        p2 = _add_peer(behavior, "peerB", set())

        behavior.subscribe("newTopic")

        # Let the background task run.
        for task in list(behavior._background_tasks):
            await task

        # Both peers should have received subscription RPCs.
        sub_peers = {p for p, r in capture.sent if r.subscriptions}
        assert p1 in sub_peers
        assert p2 in sub_peers

    @pytest.mark.asyncio
    async def test_subscribe_grafts_eligible_peers(self) -> None:
        """Subscribing GRAFTs eligible peers into the mesh."""
        behavior, capture = _make_behavior(d=2, d_low=1, d_high=4)
        behavior._running = True

        topic = "graftTopic"
        # These peers are already subscribed to the topic.
        _add_peer(behavior, "peerA", {topic})
        _add_peer(behavior, "peerB", {topic})
        _add_peer(behavior, "peerC", {topic})

        behavior.subscribe(topic)

        for task in list(behavior._background_tasks):
            await task

        # Mesh should have up to D=2 peers.
        mesh = behavior.mesh.get_mesh_peers(topic)
        assert len(mesh) <= 2
        assert len(mesh) > 0

    @pytest.mark.asyncio
    async def test_subscribe_respects_fanout_promotion(self) -> None:
        """When subscribing, fanout peers are promoted and GRAFT fills to D."""
        behavior, capture = _make_behavior(d=3, d_low=2, d_high=6)
        behavior._running = True

        topic = "promoteTopic"
        p1 = _add_peer(behavior, "peerA", {topic})

        # Create fanout first.
        behavior.mesh.update_fanout(topic, {p1})
        assert p1 in behavior.mesh.get_fanout_peers(topic)

        # Add more eligible peers.
        _add_peer(behavior, "peerB", {topic})
        _add_peer(behavior, "peerC", {topic})

        behavior.subscribe(topic)

        for task in list(behavior._background_tasks):
            await task

        # Fanout peer should have been promoted to mesh.
        mesh = behavior.mesh.get_mesh_peers(topic)
        assert p1 in mesh
        # Should not exceed D.
        assert len(mesh) <= 3

    @pytest.mark.asyncio
    async def test_unsubscribe_prunes_mesh_peers(self) -> None:
        """Unsubscribing sends PRUNE to former mesh peers."""
        behavior, capture = _make_behavior()
        behavior._running = True

        topic = "pruneTopic"
        behavior.subscribe(topic)

        p1 = _add_peer(behavior, "peerA", {topic})
        p2 = _add_peer(behavior, "peerB", {topic})
        behavior.mesh.add_to_mesh(topic, p1)
        behavior.mesh.add_to_mesh(topic, p2)

        behavior.unsubscribe(topic)

        for task in list(behavior._background_tasks):
            await task

        # PRUNE should have been sent to both former mesh peers.
        prune_rpcs = [(p, r) for p, r in capture.sent if r.control and r.control.prune]
        prune_peers = {p for p, _ in prune_rpcs}
        assert p1 in prune_peers
        assert p2 in prune_peers
