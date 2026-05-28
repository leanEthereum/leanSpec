"""Basic 2-3 peer connectivity tests.

Gossipsub is a mesh-based pub/sub protocol. Peers subscribe to topics,
form a mesh overlay, and forward messages only through mesh links.
These tests verify the fundamental subscribe-mesh-publish pipeline.
"""

from __future__ import annotations

import asyncio

import pytest

from lean_spec.node.networking.gossipsub.behavior import GossipsubMessageEvent
from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.types import TopicId

from .conftest import fast_params
from .network import GossipsubTestNetwork
from .node import GossipsubTestNode

TOPIC = TopicId("test/connectivity")


@pytest.mark.asyncio
async def test_two_peers_exchange_subscriptions(
    two_nodes: tuple[GossipsubTestNode, GossipsubTestNode],
) -> None:
    """Connecting two nodes propagates subscription state to both sides."""
    a, b = two_nodes

    a.subscribe(TOPIC)

    # Subscribing sends a SUBSCRIBE RPC to all connected peers.
    # The sleep lets the async send/receive loops deliver it.
    await asyncio.sleep(0.1)

    # B should know that A is subscribed.
    peer_state_b = b.behavior._peers.get(a.peer_id)
    assert peer_state_b is not None
    assert TOPIC in peer_state_b.subscriptions


@pytest.mark.asyncio
async def test_publish_delivers_to_subscriber(
    two_nodes: tuple[GossipsubTestNode, GossipsubTestNode],
) -> None:
    """A published message reaches a subscribing peer."""
    a, b = two_nodes

    a.subscribe(TOPIC)
    b.subscribe(TOPIC)
    await asyncio.sleep(0.1)

    # Subscriptions alone are not enough for message delivery.
    # Gossipsub requires peers to be in each other's mesh.
    # The heartbeat builds the mesh by sending GRAFT RPCs.
    await a.trigger_heartbeat()
    await b.trigger_heartbeat()
    await asyncio.sleep(0.1)

    data = b"hello"
    msg_id = GossipsubMessage.compute_id(TOPIC.encode("utf-8"), data)
    await a.publish(TOPIC, data)
    msg = await b.wait_for_message(TOPIC, timeout=3.0)

    assert msg == GossipsubMessageEvent(
        peer_id=msg.peer_id, topic=TOPIC, data=data, message_id=msg_id
    )


@pytest.mark.asyncio
async def test_publish_not_delivered_without_subscription(
    two_nodes: tuple[GossipsubTestNode, GossipsubTestNode],
) -> None:
    """Messages are not delivered to peers not subscribed to the topic."""
    a, b = two_nodes

    a.subscribe(TOPIC)
    # B does NOT subscribe. Without a subscription, B never joins
    # the mesh and never receives forwarded messages.
    await asyncio.sleep(0.1)

    await a.trigger_heartbeat()
    await b.trigger_heartbeat()
    await asyncio.sleep(0.1)

    await a.publish(TOPIC, b"nobody-listening")
    await asyncio.sleep(0.3)

    assert b.message_count(TOPIC) == 0


@pytest.mark.asyncio
async def test_bidirectional_message_exchange(
    two_nodes: tuple[GossipsubTestNode, GossipsubTestNode],
) -> None:
    """Both peers can send and receive messages on the same topic."""
    a, b = two_nodes

    a.subscribe(TOPIC)
    b.subscribe(TOPIC)
    await asyncio.sleep(0.1)

    # Mesh links are bidirectional: once formed, both sides forward.
    await a.trigger_heartbeat()
    await b.trigger_heartbeat()
    await asyncio.sleep(0.1)

    data_a = b"from-a"
    data_b = b"from-b"
    msg_id_a = GossipsubMessage.compute_id(TOPIC.encode("utf-8"), data_a)
    msg_id_b = GossipsubMessage.compute_id(TOPIC.encode("utf-8"), data_b)

    await a.publish(TOPIC, data_a)
    await b.publish(TOPIC, data_b)

    msg_b = await b.wait_for_message(TOPIC, timeout=3.0)
    msg_a = await a.wait_for_message(TOPIC, timeout=3.0)

    assert msg_b == GossipsubMessageEvent(
        peer_id=msg_b.peer_id, topic=TOPIC, data=data_a, message_id=msg_id_a
    )
    assert msg_a == GossipsubMessageEvent(
        peer_id=msg_a.peer_id, topic=TOPIC, data=data_b, message_id=msg_id_b
    )


@pytest.mark.asyncio
async def test_unsubscribe_stops_delivery(
    network: GossipsubTestNetwork,
) -> None:
    """After unsubscribing, a node no longer receives messages on that topic."""
    nodes = await network.create_nodes(2, fast_params())
    await network.start_all()
    await nodes[0].connect_to(nodes[1])

    a, b = nodes[0], nodes[1]

    a.subscribe(TOPIC)
    b.subscribe(TOPIC)
    await asyncio.sleep(0.1)

    await a.trigger_heartbeat()
    await b.trigger_heartbeat()
    await asyncio.sleep(0.1)

    # Verify delivery works first.
    await a.publish(TOPIC, b"before-unsub")
    await b.wait_for_message(TOPIC, timeout=3.0)

    # Unsubscribing sends PRUNE to mesh peers and removes the topic locally.
    # Peers drop the unsubscribed node from their mesh on receipt.
    b.unsubscribe(TOPIC)
    await asyncio.sleep(0.1)
    b.clear_messages()

    await a.publish(TOPIC, b"after-unsub")
    await asyncio.sleep(0.3)

    assert b.message_count(TOPIC) == 0
