"""
Tests for the gossipsub behavior.

Covers RPC handlers, mesh maintenance and gossip emission during the
heartbeat cycle, and message publishing with subscription broadcast.
"""

from __future__ import annotations

import time

import pytest

from lean_spec.node.networking.config import MAX_PAYLOAD_SIZE, PRUNE_BACKOFF
from lean_spec.node.networking.gossipsub.behavior import (
    GOSSIP_RETRANSMISSION,
    IDONTWANT_SIZE_THRESHOLD,
    MAX_IWANT_MESSAGE_IDS_PER_REQUEST,
    GossipsubMessageEvent,
    GossipsubPeerEvent,
)
from lean_spec.node.networking.gossipsub.mcache import SeenCache
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
from lean_spec.node.snappy import compress as snappy_compress
from tests.node.networking.gossipsub.conftest import add_peer, make_behavior, make_peer


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
        message_id = b"12345678901234567890"

        ihave = ControlIHave(topic_id=TopicId("topic"), message_ids=[message_id])
        await behavior._handle_ihave(peer_id, ihave)

        assert capture.sent == [
            (peer_id, RPC(control=ControlMessage(iwant=[ControlIWant(message_ids=[message_id])])))
        ]

    @pytest.mark.asyncio
    async def test_ihave_ignores_seen(self) -> None:
        """IHAVE for already-seen messages does not trigger IWANT."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")
        message_id = MessageId(b"12345678901234567890")

        # Mark as seen
        behavior.seen_cache.add(message_id, Timestamp(time.time()))

        ihave = ControlIHave(topic_id=TopicId("topic"), message_ids=[bytes(message_id)])
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
        message = GossipsubMessage(topic=b"topic", raw_data=b"payload")
        behavior.message_cache.put(TopicId("topic"), message)

        iwant = ControlIWant(message_ids=[bytes(message.id)])
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

    @pytest.mark.asyncio
    async def test_iwant_unknown_peer_sends_nothing(self) -> None:
        """IWANT from an untracked peer is silently ignored."""
        behavior, capture = make_behavior()
        message = GossipsubMessage(topic=b"topic", raw_data=b"payload")
        behavior.message_cache.put(TopicId("topic"), message)

        iwant = ControlIWant(message_ids=[bytes(message.id)])
        await behavior._handle_iwant(make_peer("stranger"), iwant)

        assert capture.sent == []

    @pytest.mark.asyncio
    async def test_iwant_serves_up_to_retransmission_limit_then_skips(self) -> None:
        """One message is served GOSSIP_RETRANSMISSION times then skipped."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")
        message = GossipsubMessage(topic=b"topic", raw_data=b"payload")
        behavior.message_cache.put(TopicId("topic"), message)

        iwant = ControlIWant(message_ids=[bytes(message.id)])
        for _ in range(GOSSIP_RETRANSMISSION + 2):
            await behavior._handle_iwant(peer_id, iwant)

        served_reply = (peer_id, RPC(publish=[Message(topic=TopicId("topic"), data=b"payload")]))
        assert capture.sent == [served_reply] * GOSSIP_RETRANSMISSION

    @pytest.mark.asyncio
    async def test_iwant_caps_message_ids_per_request(self) -> None:
        """Only the first MAX_IWANT_MESSAGE_IDS_PER_REQUEST IDs are processed."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        served_message = GossipsubMessage(topic=b"topic", raw_data=b"payload")
        behavior.message_cache.put(TopicId("topic"), served_message)

        # Pad the request past the cap with junk IDs, then place the cached ID
        # one slot beyond the cap so the cap must drop it.
        junk_ids = [bytes([byte_value] * 20) for byte_value in range(1, 5)]
        padding_ids = junk_ids * (MAX_IWANT_MESSAGE_IDS_PER_REQUEST // len(junk_ids) + 1)
        message_ids = padding_ids[:MAX_IWANT_MESSAGE_IDS_PER_REQUEST] + [bytes(served_message.id)]

        iwant = ControlIWant(message_ids=message_ids)
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

        message = Message(topic=topic, data=b"hello")
        await behavior._handle_message(sender, message)

        assert capture.sent == [(mesh_rx, RPC(publish=[message]))]

    @pytest.mark.asyncio
    async def test_duplicate_message_ignored(self) -> None:
        """Duplicate message is ignored (not forwarded)."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)

        peer_id = add_peer(behavior, "peer1", {topic})
        message = Message(topic=topic, data=b"hello")

        await behavior._handle_message(peer_id, message)
        assert capture.sent == []

        # Second time should be ignored
        await behavior._handle_message(peer_id, message)
        assert capture.sent == []

    @pytest.mark.asyncio
    async def test_message_event_emitted(self) -> None:
        """Received message on a subscribed topic emits GossipsubMessageEvent."""
        behavior, _ = make_behavior()
        behavior.subscribe(TopicId("topic"))
        peer_id = add_peer(behavior, "peer1")

        message = Message(topic=TopicId("topic"), data=b"payload")
        await behavior._handle_message(peer_id, message)

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

        message = Message(topic=TopicId(""), data=b"data")
        await behavior._handle_message(peer_id, message)

        assert capture.sent == []
        assert behavior._event_queue.empty()

    @pytest.mark.asyncio
    async def test_dropped_when_not_subscribed(self) -> None:
        """Message on a topic we don't subscribe to is dropped, not cached or enqueued."""
        behavior, capture = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        message = Message(topic=TopicId("topic"), data=b"data")
        message_id = GossipsubMessage.compute_id(b"topic", b"data")
        await behavior._handle_message(peer_id, message)

        assert capture.sent == []
        assert behavior._event_queue.empty()
        assert behavior.seen_cache.has(message_id) is False
        assert behavior.message_cache.get(message_id) is None

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
        message = Message(topic=topic, data=large_data)
        message_id = GossipsubMessage.compute_id(topic.encode("utf-8"), large_data)
        await behavior._handle_message(sender, message)

        assert capture.sent == [
            (other, RPC(publish=[message])),
            (
                other,
                RPC(
                    control=ControlMessage(
                        idontwant=[ControlIDontWant(message_ids=[bytes(message_id)])]
                    )
                ),
            ),
        ]

    @pytest.mark.asyncio
    async def test_oversized_decompressed_payload_rejected(self) -> None:
        """A payload that decompresses past the wire limit is dropped before caching."""
        behavior, capture = make_behavior()
        topic = TopicId("test_topic")
        behavior.subscribe(topic)
        peer_id = add_peer(behavior, "peer1", {topic})

        # Highly compressible bytes that expand one byte past the 10 MiB cap.
        oversized_payload = b"\x00" * (MAX_PAYLOAD_SIZE + 1)
        compressed_payload = snappy_compress(oversized_payload)
        message = Message(topic=topic, data=compressed_payload)
        message_id = GossipsubMessage.compute_id(topic.encode("utf-8"), oversized_payload)
        await behavior._handle_message(peer_id, message)

        assert capture.sent == []
        assert behavior._event_queue.empty()
        assert behavior.seen_cache.has(message_id) is False
        assert behavior.message_cache.get(message_id) is None

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
        message = Message(topic=topic, data=small_data)
        await behavior._handle_message(sender, message)

        assert capture.sent == [(other, RPC(publish=[message]))]

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

        message_id = GossipsubMessage.compute_id(topic.encode("utf-8"), b"hello")

        # peer_ax says it doesn't want this message
        behavior._peers[peer_ax].dont_want_ids.add(message_id)

        message = Message(topic=topic, data=b"hello")
        await behavior._handle_message(sender, message)

        assert capture.sent == []


class TestHandleIDontWant:
    """Tests for IDONTWANT handling."""

    def test_idontwant_populates_peer_set(self) -> None:
        """IDONTWANT adds message IDs to peer's dont_want set."""
        behavior, _ = make_behavior()
        peer_id = add_peer(behavior, "peer1")

        message_ids = [b"12345678901234567890", b"abcdefghijklmnopqrst"]
        idontwant = ControlIDontWant(message_ids=message_ids)
        behavior._handle_idontwant(peer_id, idontwant)

        state = behavior._peers[peer_id]
        for mid in message_ids:
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
        assert {peer_id for peer_id, _ in capture.sent} == expected_peers
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
        pruned_peers = {peer_id for peer_id, _ in capture.sent}
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
        message = GossipsubMessage(topic=topic.encode("utf-8"), raw_data=b"data")
        behavior.message_cache.put(topic, message)

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
                        ihave=[ControlIHave(topic_id=topic, message_ids=[message.id])]
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

        message = GossipsubMessage(topic=topic.encode("utf-8"), raw_data=b"data")
        behavior.message_cache.put(topic, message)

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

        message = GossipsubMessage(topic=b"topic", raw_data=b"data")
        behavior.message_cache.put(TopicId("topic"), message)

        assert behavior.message_cache.has(message.id)

        # Run heartbeat several times to shift through all windows
        for _ in range(7):
            await behavior._heartbeat()

        # After enough shifts, old messages should be evicted
        assert not behavior.message_cache.has(message.id)

    @pytest.mark.asyncio
    async def test_cleans_seen_cache(self) -> None:
        """Heartbeat cleans expired entries from seen cache."""
        behavior, _ = make_behavior()
        behavior.seen_cache = SeenCache(ttl_seconds=1)

        message_id = MessageId(b"12345678901234567890")
        behavior.seen_cache.add(message_id, Timestamp(time.time() - 10))  # Already expired

        await behavior._heartbeat()

        assert not behavior.seen_cache.has(message_id)

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
    async def test_clears_iwant_served_counts(self) -> None:
        """Heartbeat resets per-peer IWANT retransmission budgets."""
        behavior, _ = make_behavior()
        pid = add_peer(behavior, "peer1")
        behavior._peers[pid].iwant_served_counts[MessageId(b"12345678901234567890")] = 3

        assert len(behavior._peers[pid].iwant_served_counts) == 1

        await behavior._heartbeat()

        assert len(behavior._peers[pid].iwant_served_counts) == 0

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
        message = GossipsubMessage(topic=fan_topic.encode("utf-8"), raw_data=b"data")
        behavior.message_cache.put(fan_topic, message)

        await behavior._heartbeat()

        # Heartbeat emits gossip for fanout topics.
        # Filter to IHAVE RPCs for the fanout topic.
        fanout_ihaves = [
            (peer_id, rpc)
            for peer_id, rpc in capture.sent
            if rpc.control and any(ihave.topic_id == fan_topic for ihave in rpc.control.ihave)
        ]
        assert fanout_ihaves == [
            (
                fan_peer,
                RPC(
                    control=ControlMessage(
                        ihave=[ControlIHave(topic_id=fan_topic, message_ids=[message.id])]
                    )
                ),
            )
        ]


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
        assert {peer_id for peer_id, _ in capture.sent} == {p1, p2}
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

        message_id = GossipsubMessage.compute_id(topic.encode("utf-8"), b"cacheMe")
        assert behavior.seen_cache.has(message_id)
        assert behavior.message_cache.has(message_id)

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
        sub_sends = [(peer_id, rpc) for peer_id, rpc in capture.sent if rpc.subscriptions]
        prune_sends = [
            (peer_id, rpc) for peer_id, rpc in capture.sent if rpc.control and rpc.control.prune
        ]
        assert sub_sends == [(p1, sub_rpc), (p2, sub_rpc)]
        assert {peer_id for peer_id, _ in prune_sends} == {p1, p2}
        assert all(rpc == prune_rpc for _, rpc in prune_sends)
