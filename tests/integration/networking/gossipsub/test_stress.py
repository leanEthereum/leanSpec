"""Stress and edge case tests."""

from __future__ import annotations

import asyncio

import pytest

from lean_spec.node.networking.gossipsub.behavior import GossipsubMessageEvent
from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.types import TopicId
from tests.integration.networking.gossipsub.conftest import fast_params
from tests.integration.networking.gossipsub.network import GossipsubTestNetwork

TOPIC = TopicId("test/stress")


@pytest.mark.asyncio
async def test_rapid_subscribe_unsubscribe(
    network: GossipsubTestNetwork,
) -> None:
    """10 rapid subscribe/unsubscribe cycles: no crash, consistent state."""

    # Each subscribe/unsubscribe cycle triggers GRAFT/PRUNE exchanges.
    # Rapid cycling exposes race conditions in mesh state tracking.
    # A correct implementation must not crash or deadlock.
    params = fast_params()
    nodes = await network.create_nodes(3, params)
    await network.start_all()
    await network.connect_full()

    target = nodes[0]

    for _ in range(10):
        target.subscribe(TOPIC)
        await asyncio.sleep(0.02)
        target.unsubscribe(TOPIC)
        await asyncio.sleep(0.02)

    # Final subscribe to verify state is consistent.
    target.subscribe(TOPIC)
    await asyncio.sleep(0.1)
    await network.trigger_all_heartbeats()
    await asyncio.sleep(0.1)

    # Should have a valid subscription state.
    assert TOPIC in target.behavior.mesh.subscriptions


@pytest.mark.asyncio
async def test_concurrent_publish(
    network: GossipsubTestNetwork,
) -> None:
    """5 nodes publish simultaneously: each receives 4 messages."""
    params = fast_params()
    nodes = await network.create_nodes(5, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=5)

    # All 5 nodes publish at the same time.
    # This tests concurrent access to shared mesh state and message caches.
    payloads = [f"concurrent-{i}".encode() for i in range(5)]
    all_message_ids = {p: GossipsubMessage.compute_id(TOPIC.encode("utf-8"), p) for p in payloads}

    await asyncio.gather(*(node.publish(TOPIC, payloads[i]) for i, node in enumerate(nodes)))

    # Each node publishes one message but does not deliver its own.
    # So each expects exactly the 4 messages from the other publishers.
    for i, node in enumerate(nodes):
        messages = await node.wait_for_messages(4, TOPIC, timeout=10.0)
        expected_data = {payloads[j] for j in range(5) if j != i}
        assert {message.data for message in messages} == expected_data, (
            f"{node.peer_id}: expected {expected_data}, got {[m.data for m in messages]}"
        )
        for message in messages:
            assert message == GossipsubMessageEvent(
                peer_id=message.peer_id,
                topic=TOPIC,
                data=message.data,
                message_id=all_message_ids[message.data],
            )


@pytest.mark.asyncio
async def test_large_network_ring(
    network: GossipsubTestNetwork,
) -> None:
    """20 nodes in ring: message reaches all."""

    # Ring topology with D=2: each node has at most 2 mesh neighbors.
    # A message must traverse up to 10 hops to reach the far side.
    # Lazy gossip (IHAVE/IWANT) via D_lazy fills any gaps that eager
    # forwarding misses along the way.
    params = fast_params(d=2, d_low=1, d_high=4, d_lazy=1)
    await network.create_nodes(20, params)
    await network.start_all()
    await network.connect_ring()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=5)

    data = b"ring-message"
    message_id = GossipsubMessage.compute_id(TOPIC.encode("utf-8"), data)
    await network.nodes[0].publish(TOPIC, data)

    # All other nodes should receive the message.
    for node in network.nodes[1:]:
        message = await node.wait_for_message(TOPIC, timeout=10.0)
        assert message == GossipsubMessageEvent(
            peer_id=message.peer_id, topic=TOPIC, data=data, message_id=message_id
        )
