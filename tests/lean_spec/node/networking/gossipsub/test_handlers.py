"""Tests for gossipsub RPC handlers."""

from __future__ import annotations

import time

import pytest

from lean_spec.node.networking.config import PRUNE_BACKOFF
from lean_spec.node.networking.gossipsub.behavior import (
    IDONTWANT_SIZE_THRESHOLD,
    GossipsubMessageEvent,
    GossipsubPeerEvent,
)
from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.rpc import (
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
from lean_spec.node.networking.gossipsub.types import MessageId, Timestamp, TopicId

from .conftest import add_peer, make_behavior, make_peer


class TestHandleGraft:
    """Tests for GRAFT request handling."""

    @pytest.mark.asyncio
    async def test_accept_graft_when_subscribed(self) -> None:
        """Accept GRAFT when we are subscribed and mesh has capacity."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        peer_id = add_peer(behavior, "peer1", {topic})
        graft = ControlGraft(topic_id=topic)

        await behavior._handle_graft(peer_id, graft)

        # Peer should be added to mesh
        assert peer_id in behavior.mesh.get_mesh_peers(topic)
        # No PRUNE sent
        assert capture.sent == []

    @pytest.mark.asyncio
    async def test_ignore_graft_not_subscribed(self) -> None:
        """Silently ignore GRAFT for unknown topics (v1.1 spec)."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")
        graft = ControlGraft(topic_id=TopicId("unknown_topic"))

        await behavior._handle_graft(peer_id, graft)

        # No PRUNE sent -- silent ignore prevents amplification attacks.
        assert capture.sent == []

    @pytest.mark.asyncio
    async def test_reject_graft_mesh_full(self) -> None:
        """Reject GRAFT with PRUNE when mesh is at d_high."""
        behavior, capture = make_behavior(d_high=2)
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        # Fill mesh to d_high
        add_peer(behavior, "meshA", {topic})
        add_peer(behavior, "meshB", {topic})
        behavior.mesh.add_to_mesh(topic, make_peer("meshA"))
        behavior.mesh.add_to_mesh(topic, make_peer("meshB"))

        # New peer tries to GRAFT
        peer_id = add_peer(behavior, "newPeer", {topic})
        await behavior._handle_graft(peer_id, ControlGraft(topic_id=topic))

        assert capture.sent == [
            (
                peer_id,
                RPC(
                    control=ControlMessage(
                        prune=[ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)]
                    )
                ),
            )
        ]

    @pytest.mark.asyncio
    async def test_reject_graft_in_backoff(self) -> None:
        """Reject GRAFT when peer is in backoff period."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        peer_id = add_peer(behavior, "peer1", {topic})
        # Set backoff far in the future
        behavior._peers[peer_id].backoff[topic] = time.time() + 999

        await behavior._handle_graft(peer_id, ControlGraft(topic_id=topic))

        assert capture.sent == [
            (
                peer_id,
                RPC(
                    control=ControlMessage(
                        prune=[ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)]
                    )
                ),
            )
        ]

    @pytest.mark.asyncio
    async def test_graft_idempotent(self) -> None:
        """Double GRAFT is idempotent -- peer stays in mesh, no PRUNE."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        peer_id = add_peer(behavior, "peer1", {topic})
        graft = ControlGraft(topic_id=topic)

        await behavior._handle_graft(peer_id, graft)
        await behavior._handle_graft(peer_id, graft)

        assert peer_id in behavior.mesh.get_mesh_peers(topic)
        assert capture.sent == []


class TestHandlePrune:
    """Tests for PRUNE notification handling."""

    @pytest.mark.asyncio
    async def test_prune_removes_from_mesh(self) -> None:
        """PRUNE removes peer from mesh."""
        behavior, _ = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        peer_id = add_peer(behavior, "peer1", {topic})
        behavior.mesh.add_to_mesh(topic, peer_id)
        assert peer_id in behavior.mesh.get_mesh_peers(topic)

        prune = ControlPrune(topic_id=topic, backoff=60)
        await behavior._handle_prune(peer_id, prune)

        assert peer_id not in behavior.mesh.get_mesh_peers(topic)

    @pytest.mark.asyncio
    async def test_prune_sets_backoff(self) -> None:
        """PRUNE sets backoff timer on peer state."""
        behavior, _ = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        peer_id = add_peer(behavior, "peer1", {topic})
        behavior.mesh.add_to_mesh(topic, peer_id)

        before = time.time()
        prune = ControlPrune(topic_id=topic, backoff=120)
        await behavior._handle_prune(peer_id, prune)

        state = behavior._peers[peer_id]
        assert topic in state.backoff
        assert state.backoff[topic] >= before + 120

    @pytest.mark.asyncio
    async def test_prune_zero_backoff_no_timer(self) -> None:
        """PRUNE with zero backoff does not set a timer."""
        behavior, _ = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        peer_id = add_peer(behavior, "peer1", {topic})

        prune = ControlPrune(topic_id=topic, backoff=0)
        await behavior._handle_prune(peer_id, prune)

        state = behavior._peers[peer_id]
        assert topic not in state.backoff

    @pytest.mark.asyncio
    async def test_prune_unknown_peer(self) -> None:
        """PRUNE for unknown peer does not crash."""
        behavior, _ = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        unknown_peer = make_peer("unknown")
        # No crash expected
        prune = ControlPrune(topic_id=topic, backoff=60)
        await behavior._handle_prune(unknown_peer, prune)


class TestHandleIHave:
    """Tests for IHAVE advertisement handling."""

    @pytest.mark.asyncio
    async def test_ihave_sends_iwant_for_unseen(self) -> None:
        """IHAVE for unseen messages triggers IWANT."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")
        msg_id = b"12345678901234567890"

        ihave = ControlIHave(topic_id=TopicId("topic"), message_ids=[msg_id])
        await behavior._handle_ihave(peer_id, ihave)

        assert capture.sent == [
            (peer_id, RPC(control=ControlMessage(iwant=[ControlIWant(message_ids=[msg_id])])))
        ]

    @pytest.mark.asyncio
    async def test_ihave_ignores_seen(self) -> None:
        """IHAVE for already-seen messages does not trigger IWANT."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")
        msg_id = MessageId(b"12345678901234567890")

        # Mark as seen
        behavior.seen_cache.add(msg_id, Timestamp(time.time()))

        ihave = ControlIHave(topic_id=TopicId("topic"), message_ids=[bytes(msg_id)])
        await behavior._handle_ihave(peer_id, ihave)

        assert capture.sent == []

    @pytest.mark.asyncio
    async def test_ihave_partial_seen(self) -> None:
        """IHAVE with mix of seen and unseen only requests unseen."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        seen_id = MessageId(b"seen_msg_id_1234seen")
        unseen_id = b"unseen_msg_id_12unse"

        behavior.seen_cache.add(seen_id, Timestamp(time.time()))

        ihave = ControlIHave(topic_id=TopicId("topic"), message_ids=[bytes(seen_id), unseen_id])
        await behavior._handle_ihave(peer_id, ihave)

        assert capture.sent == [
            (
                peer_id,
                RPC(control=ControlMessage(iwant=[ControlIWant(message_ids=[unseen_id])])),
            )
        ]

    @pytest.mark.asyncio
    async def test_ihave_skips_wrong_length_ids(self) -> None:
        """IHAVE ignores message IDs that are not 20 bytes."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        # Only wrong-length IDs
        ihave = ControlIHave(topic_id=TopicId("topic"), message_ids=[b"short", b"toolong" * 10])
        await behavior._handle_ihave(peer_id, ihave)

        # No IWANT sent
        assert capture.sent == []


class TestHandleIWant:
    """Tests for IWANT request handling."""

    @pytest.mark.asyncio
    async def test_iwant_responds_with_cached(self) -> None:
        """IWANT for cached messages responds with full messages."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        # Put a message in cache
        msg = GossipsubMessage(topic=b"topic", raw_data=b"payload")
        behavior.message_cache.put(TopicId("topic"), msg)

        iwant = ControlIWant(message_ids=[bytes(msg.id)])
        await behavior._handle_iwant(peer_id, iwant)

        assert capture.sent == [
            (peer_id, RPC(publish=[Message(topic=TopicId("topic"), data=b"payload")]))
        ]

    @pytest.mark.asyncio
    async def test_iwant_ignores_uncached(self) -> None:
        """IWANT for uncached messages sends nothing."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        iwant = ControlIWant(message_ids=[b"12345678901234567890"])
        await behavior._handle_iwant(peer_id, iwant)

        assert capture.sent == []

    @pytest.mark.asyncio
    async def test_iwant_skips_wrong_length_ids(self) -> None:
        """IWANT ignores message IDs that are not 20 bytes."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        iwant = ControlIWant(message_ids=[b"short"])
        await behavior._handle_iwant(peer_id, iwant)

        assert capture.sent == []


class TestHandleSubscription:
    """Tests for subscription change handling."""

    @pytest.mark.asyncio
    async def test_subscribe_adds_to_peer_state(self) -> None:
        """Subscribe adds topic to peer's subscription set."""
        behavior, _ = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        sub = SubOpts(subscribe=True, topic_id=TopicId("topic1"))
        await behavior._handle_subscription(peer_id, sub)

        assert TopicId("topic1") in behavior._peers[peer_id].subscriptions

    @pytest.mark.asyncio
    async def test_unsubscribe_removes_and_cleans_mesh(self) -> None:
        """Unsubscribe removes topic and cleans mesh."""
        behavior, _ = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        peer_id = add_peer(behavior, "peer1", {TopicId("test_topic")})
        behavior.mesh.add_to_mesh(topic, peer_id)

        sub = SubOpts(subscribe=False, topic_id=topic)
        await behavior._handle_subscription(peer_id, sub)

        assert topic not in behavior._peers[peer_id].subscriptions
        assert peer_id not in behavior.mesh.get_mesh_peers(topic)

    @pytest.mark.asyncio
    async def test_subscription_emits_peer_event(self) -> None:
        """Subscription change emits GossipsubPeerEvent."""
        behavior, _ = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        sub = SubOpts(subscribe=True, topic_id=TopicId("topic1"))
        await behavior._handle_subscription(peer_id, sub)

        assert behavior._event_queue.get_nowait() == GossipsubPeerEvent(
            peer_id=peer_id, topic=TopicId("topic1"), subscribed=True
        )


class TestHandleMessage:
    """Tests for published message handling."""

    @pytest.mark.asyncio
    async def test_new_message_forwarded_excluding_sender(self) -> None:
        """New message is forwarded to mesh peers, excluding sender."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        sender = add_peer(behavior, "senderX", {topic})
        mesh_rx = add_peer(behavior, "meshRx", {topic})
        behavior.mesh.add_to_mesh(topic, sender)
        behavior.mesh.add_to_mesh(topic, mesh_rx)

        msg = Message(topic=topic, data=b"hello")
        await behavior._handle_message(sender, msg)

        assert capture.sent == [(mesh_rx, RPC(publish=[msg]))]

    @pytest.mark.asyncio
    async def test_duplicate_message_ignored(self) -> None:
        """Duplicate message is ignored (not forwarded)."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        peer_id = add_peer(behavior, "peer1", {topic})
        msg = Message(topic=topic, data=b"hello")

        await behavior._handle_message(peer_id, msg)
        assert capture.sent == []

        # Second time should be ignored
        await behavior._handle_message(peer_id, msg)
        assert capture.sent == []

    @pytest.mark.asyncio
    async def test_message_event_emitted(self) -> None:
        """Received message emits GossipsubMessageEvent."""
        behavior, _ = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        msg = Message(topic=TopicId("topic"), data=b"payload")
        await behavior._handle_message(peer_id, msg)

        assert behavior._event_queue.get_nowait() == GossipsubMessageEvent(
            peer_id=peer_id,
            topic=TopicId("topic"),
            data=b"payload",
            message_id=GossipsubMessage.compute_id(b"topic", b"payload"),
        )

    @pytest.mark.asyncio
    async def test_empty_topic_ignored(self) -> None:
        """Message with empty topic is silently dropped."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        msg = Message(topic=TopicId(""), data=b"data")
        await behavior._handle_message(peer_id, msg)

        assert capture.sent == []
        assert behavior._event_queue.empty()

    @pytest.mark.asyncio
    async def test_not_forwarded_when_not_subscribed(self) -> None:
        """Message is not forwarded when we're not subscribed to the topic."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        # Not subscribed to "topic"
        msg = Message(topic=TopicId("topic"), data=b"data")
        await behavior._handle_message(peer_id, msg)

        assert capture.sent == []
        assert behavior._event_queue.get_nowait() == GossipsubMessageEvent(
            peer_id=peer_id,
            topic=TopicId("topic"),
            data=b"data",
            message_id=GossipsubMessage.compute_id(b"topic", b"data"),
        )

    @pytest.mark.asyncio
    async def test_idontwant_sent_for_large_messages(self) -> None:
        """IDONTWANT is sent to mesh peers for messages >= threshold."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        sender = add_peer(behavior, "senderX", {topic})
        other = add_peer(behavior, "otherMesh", {topic})
        behavior.mesh.add_to_mesh(topic, sender)
        behavior.mesh.add_to_mesh(topic, other)

        large_data = b"x" * IDONTWANT_SIZE_THRESHOLD
        msg = Message(topic=topic, data=large_data)
        msg_id = GossipsubMessage.compute_id(topic.encode("utf-8"), large_data)
        await behavior._handle_message(sender, msg)

        assert capture.sent == [
            (other, RPC(publish=[msg])),
            (
                other,
                RPC(
                    control=ControlMessage(
                        idontwant=[ControlIDontWant(message_ids=[bytes(msg_id)])]
                    )
                ),
            ),
        ]

    @pytest.mark.asyncio
    async def test_idontwant_not_sent_for_small_messages(self) -> None:
        """IDONTWANT is NOT sent for messages below size threshold."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        sender = add_peer(behavior, "senderX", {topic})
        other = add_peer(behavior, "otherMesh", {topic})
        behavior.mesh.add_to_mesh(topic, sender)
        behavior.mesh.add_to_mesh(topic, other)

        small_data = b"x" * (IDONTWANT_SIZE_THRESHOLD - 1)
        msg = Message(topic=topic, data=small_data)
        await behavior._handle_message(sender, msg)

        assert capture.sent == [(other, RPC(publish=[msg]))]

    @pytest.mark.asyncio
    async def test_message_not_forwarded_to_idontwant_peer(self) -> None:
        """Messages are not forwarded to peers who sent IDONTWANT."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        sender = add_peer(behavior, "senderX", {topic})
        peer_ax = add_peer(behavior, "peerAx", {topic})
        behavior.mesh.add_to_mesh(topic, sender)
        behavior.mesh.add_to_mesh(topic, peer_ax)

        msg_id = GossipsubMessage.compute_id(topic.encode("utf-8"), b"hello")

        # peer_ax says it doesn't want this message
        behavior._peers[peer_ax].dont_want_ids.add(msg_id)

        msg = Message(topic=topic, data=b"hello")
        await behavior._handle_message(sender, msg)

        assert capture.sent == []


class TestHandleIDontWant:
    """Tests for IDONTWANT handling."""

    def test_idontwant_populates_peer_set(self) -> None:
        """IDONTWANT adds message IDs to peer's dont_want set."""
        behavior, _ = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        msg_ids = [b"12345678901234567890", b"abcdefghijklmnopqrst"]
        idontwant = ControlIDontWant(message_ids=msg_ids)
        behavior._handle_idontwant(peer_id, idontwant)

        state = behavior._peers[peer_id]
        for mid in msg_ids:
            assert MessageId(mid) in state.dont_want_ids

    def test_idontwant_unknown_peer(self) -> None:
        """IDONTWANT for unknown peer is silently ignored."""
        behavior, _ = make_behavior()
        unknown = make_peer("unknown")

        idontwant = ControlIDontWant(message_ids=[b"msg"])
        # Should not raise
        behavior._handle_idontwant(unknown, idontwant)


class TestHandleRPC:
    """Tests for full RPC dispatch."""

    @pytest.mark.asyncio
    async def test_dispatches_all_components(self) -> None:
        """RPC with subscriptions, messages, and control is fully dispatched."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)
        peer_id = add_peer(behavior, "peer1", {topic})

        rpc = RPC(
            subscriptions=[SubOpts(subscribe=True, topic_id=TopicId("new_topic"))],
            publish=[Message(topic=topic, data=b"data")],
            control=ControlMessage(graft=[ControlGraft(topic_id=topic)]),
        )

        await behavior._handle_rpc(peer_id, rpc)

        assert TopicId("new_topic") in behavior._peers[peer_id].subscriptions
        assert peer_id in behavior.mesh.get_mesh_peers(topic)
        assert capture.sent == []

        events = []
        while not behavior._event_queue.empty():
            events.append(behavior._event_queue.get_nowait())
        assert events == [
            GossipsubPeerEvent(peer_id=peer_id, topic=TopicId("new_topic"), subscribed=True),
            GossipsubMessageEvent(
                peer_id=peer_id,
                topic=topic,
                data=b"data",
                message_id=GossipsubMessage.compute_id(topic.encode("utf-8"), b"data"),
            ),
        ]

    @pytest.mark.asyncio
    async def test_unknown_peer_is_noop(self) -> None:
        """RPC from unknown peer is silently ignored."""
        behavior, capture = make_behavior()
        unknown = make_peer("unknown")

        rpc = RPC(subscriptions=[SubOpts(subscribe=True, topic_id=TopicId("topic"))])
        await behavior._handle_rpc(unknown, rpc)

        assert capture.sent == []
