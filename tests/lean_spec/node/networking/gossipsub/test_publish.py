"""Tests for gossipsub publish and broadcast subscription.

Tests cover the publish() method, fanout publishing, deduplication,
and subscription broadcast with GRAFT/PRUNE coordination.
"""

from __future__ import annotations

import pytest

from lean_spec.node.networking.config import PRUNE_BACKOFF
from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.rpc import (
    RPC,
    ControlMessage,
    ControlPrune,
    Message,
    SubOpts,
)
from lean_spec.node.networking.gossipsub.types import TopicId

from .conftest import add_peer, make_behavior


class TestPublish:
    """Tests for the publish() method."""

    @pytest.mark.asyncio
    async def test_publish_to_subscribed_topic(self) -> None:
        """Published message reaches mesh peers for a subscribed topic."""
        behavior, capture = make_behavior(d=3, d_low=2, d_high=6)
        topic = TopicId("testTopic")
        behavior.subscribe(topic)

        p1 = add_peer(behavior, "peerA", {topic})
        p2 = add_peer(behavior, "peerB", {topic})
        behavior.mesh.add_to_mesh(topic, p1)
        behavior.mesh.add_to_mesh(topic, p2)

        await behavior.publish(topic, b"hello")

        publish_rpc = RPC(publish=[Message(topic=topic, data=b"hello")])
        assert {p for p, _ in capture.sent} == {p1, p2}
        assert all(rpc == publish_rpc for _, rpc in capture.sent)

    @pytest.mark.asyncio
    async def test_publish_to_unsubscribed_topic_uses_fanout(self) -> None:
        """Publishing to an unsubscribed topic uses fanout peers."""
        behavior, capture = make_behavior(d=2, d_low=1, d_high=4)

        topic = TopicId("fanoutTopic")
        add_peer(behavior, "peerA", {topic})
        add_peer(behavior, "peerB", {topic})

        await behavior.publish(topic, b"fanoutMsg")

        publish_rpc = RPC(publish=[Message(topic=topic, data=b"fanoutMsg")])
        assert len(capture.sent) > 0
        assert all(rpc == publish_rpc for _, rpc in capture.sent)
        assert topic in behavior.mesh.fanout_topics

    @pytest.mark.asyncio
    async def test_publish_duplicate_skipped(self) -> None:
        """Publishing the same message twice is a no-op the second time."""
        behavior, capture = make_behavior()
        topic = TopicId("testTopic")
        behavior.subscribe(topic)

        p1 = add_peer(behavior, "peerA", {topic})
        behavior.mesh.add_to_mesh(topic, p1)

        await behavior.publish(topic, b"payload")
        first_count = len(capture.sent)

        await behavior.publish(topic, b"payload")
        assert len(capture.sent) == first_count

    @pytest.mark.asyncio
    async def test_publish_caches_message(self) -> None:
        """Published messages are added to the message cache."""
        behavior, _ = make_behavior()
        topic = TopicId("testTopic")
        behavior.subscribe(topic)

        await behavior.publish(topic, b"cacheMe")

        msg_id = GossipsubMessage.compute_id(topic.encode("utf-8"), b"cacheMe")
        assert behavior.seen_cache.has(msg_id)
        assert behavior.message_cache.has(msg_id)

    @pytest.mark.asyncio
    async def test_publish_empty_mesh_no_crash(self) -> None:
        """Publishing to an empty mesh does not crash."""
        behavior, capture = make_behavior()
        topic = TopicId("emptyTopic")
        behavior.subscribe(topic)

        # No peers added -- mesh is empty.
        await behavior.publish(topic, b"data")

        assert capture.sent == []


class TestBroadcastSubscription:
    """Tests for _broadcast_subscription (via subscribe/unsubscribe)."""

    @pytest.mark.asyncio
    async def test_subscribe_sends_subscription_to_all_peers(self) -> None:
        """Subscribing broadcasts a subscription RPC to all peers."""
        behavior, capture = make_behavior(d=2, d_low=1, d_high=4)
        behavior._stop_event.clear()

        p1 = add_peer(behavior, "peerA", set())
        p2 = add_peer(behavior, "peerB", set())

        behavior.subscribe(TopicId("newTopic"))

        # Let the background task run.
        for task in list(behavior._background_tasks):
            await task

        sub_rpc = RPC(subscriptions=[SubOpts(subscribe=True, topic_id=TopicId("newTopic"))])
        assert capture.sent == [(p1, sub_rpc), (p2, sub_rpc)]

    @pytest.mark.asyncio
    async def test_subscribe_grafts_eligible_peers(self) -> None:
        """Subscribing GRAFTs eligible peers into the mesh."""
        behavior, capture = make_behavior(d=2, d_low=1, d_high=4)
        behavior._stop_event.clear()

        topic = TopicId("graftTopic")
        # These peers are already subscribed to the topic.
        add_peer(behavior, "peerA", {topic})
        add_peer(behavior, "peerB", {topic})
        add_peer(behavior, "peerC", {topic})

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
        behavior, capture = make_behavior(d=3, d_low=2, d_high=6)
        behavior._stop_event.clear()

        topic = TopicId("promoteTopic")
        p1 = add_peer(behavior, "peerA", {topic})

        # Create fanout first.
        behavior.mesh.update_fanout(topic, {p1})
        assert p1 in behavior.mesh.get_fanout_peers(topic)

        # Add more eligible peers.
        add_peer(behavior, "peerB", {topic})
        add_peer(behavior, "peerC", {topic})

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
        behavior, capture = make_behavior()
        behavior._stop_event.clear()

        topic = TopicId("pruneTopic")
        behavior.subscribe(topic)

        p1 = add_peer(behavior, "peerA", {topic})
        p2 = add_peer(behavior, "peerB", {topic})
        behavior.mesh.add_to_mesh(topic, p1)
        behavior.mesh.add_to_mesh(topic, p2)

        # Drain background tasks from subscribe() before testing unsubscribe.
        for task in list(behavior._background_tasks):
            await task
        capture.sent.clear()

        behavior.unsubscribe(topic)

        for task in list(behavior._background_tasks):
            await task

        sub_rpc = RPC(subscriptions=[SubOpts(subscribe=False, topic_id=topic)])
        prune_rpc = RPC(
            control=ControlMessage(prune=[ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)])
        )
        sub_sends = [(p, r) for p, r in capture.sent if r.subscriptions]
        prune_sends = [(p, r) for p, r in capture.sent if r.control and r.control.prune]
        assert sub_sends == [(p1, sub_rpc), (p2, sub_rpc)]
        assert {p for p, _ in prune_sends} == {p1, p2}
        assert all(rpc == prune_rpc for _, rpc in prune_sends)
