"""Multi-hop message propagation tests."""

from __future__ import annotations

import asyncio

import pytest

from lean_spec.node.networking.gossipsub.behavior import GossipsubMessageEvent
from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.types import TopicId

from .conftest import fast_params
from .network import GossipsubTestNetwork

TOPIC = TopicId("test/propagation")


@pytest.mark.asyncio
async def test_chain_propagation(
    network: GossipsubTestNetwork,
) -> None:
    """5-node chain: a message from node 0 reaches all nodes."""

    # D=2 with a chain topology means each node has at most 2 mesh peers.
    # A message from node 0 must hop through each link: 0->1->2->3->4.
    # This proves gossipsub delivers across multiple hops, not just direct peers.
    params = fast_params(d=2, d_low=1, d_high=3)
    await network.create_nodes(5, params)
    await network.start_all()
    await network.connect_chain()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=5)

    data = b"chain-msg"
    message_id = GossipsubMessage.compute_id(TOPIC.encode("utf-8"), data)
    await network.nodes[0].publish(TOPIC, data)

    # All other nodes should receive the message.
    for node in network.nodes[1:]:
        message = await node.wait_for_message(TOPIC, timeout=5.0)
        assert message == GossipsubMessageEvent(
            peer_id=message.peer_id, topic=TOPIC, data=data, message_id=message_id
        )


@pytest.mark.asyncio
async def test_full_mesh_all_receive(
    network: GossipsubTestNetwork,
) -> None:
    """8 nodes: all 7 non-publishers receive exactly once."""
    params = fast_params()
    await network.create_nodes(8, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=5)

    publisher = network.nodes[0]
    data = b"broadcast"
    message_id = GossipsubMessage.compute_id(TOPIC.encode("utf-8"), data)
    await publisher.publish(TOPIC, data)

    for node in network.nodes[1:]:
        message = await node.wait_for_message(TOPIC, timeout=5.0)
        assert message == GossipsubMessageEvent(
            peer_id=message.peer_id, topic=TOPIC, data=data, message_id=message_id
        )

    # In a full mesh, multiple paths exist to each node.
    # The seen-message cache must suppress duplicates so each node
    # delivers the message to the application exactly once.
    await asyncio.sleep(0.3)
    for node in network.nodes[1:]:
        assert node.message_count(TOPIC) == 1, (
            f"{node.peer_id} received {node.message_count(TOPIC)} messages (expected 1)"
        )


@pytest.mark.asyncio
async def test_duplicate_suppression(
    network: GossipsubTestNetwork,
) -> None:
    """4 fully connected nodes: each receives message exactly once."""

    # With 4 fully connected nodes, every node is a mesh peer of every other.
    # When node 0 publishes, nodes 1-3 all receive the message directly.
    # Each receiver also forwards to its other mesh peers, creating duplicates.
    # The seen-message cache must reject these redundant copies.
    params = fast_params()
    await network.create_nodes(4, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=3)

    await network.nodes[0].publish(TOPIC, b"dedup-test")

    for node in network.nodes[1:]:
        await node.wait_for_message(TOPIC, timeout=3.0)

    # Allow time for redundant forwards to arrive, then verify exactly one delivery.
    await asyncio.sleep(0.3)
    for node in network.nodes[1:]:
        assert node.message_count(TOPIC) == 1


@pytest.mark.asyncio
async def test_many_messages_all_delivered(
    network: GossipsubTestNetwork,
) -> None:
    """20 messages published: all delivered to all 4 subscribers."""
    params = fast_params()
    await network.create_nodes(4, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=3)

    publisher = network.nodes[0]
    message_count = 20

    payloads = [f"msg-{i}".encode() for i in range(message_count)]
    message_ids = [GossipsubMessage.compute_id(TOPIC.encode("utf-8"), p) for p in payloads]

    for payload in payloads:
        await publisher.publish(TOPIC, payload)

        # Without a delay, messages queue up faster than the event loop
        # can process forwarding. This causes back-pressure and dropped messages.
        await asyncio.sleep(0.01)

    for node in network.nodes[1:]:
        messages = await node.wait_for_messages(message_count, TOPIC, timeout=10.0)
        assert messages == [
            GossipsubMessageEvent(
                peer_id=messages[i].peer_id,
                topic=TOPIC,
                data=payloads[i],
                message_id=message_ids[i],
            )
            for i in range(message_count)
        ]
