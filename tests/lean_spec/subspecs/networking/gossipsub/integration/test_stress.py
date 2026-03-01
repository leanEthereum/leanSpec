"""Stress and edge case tests."""

from __future__ import annotations

import asyncio

import pytest

from lean_spec.subspecs.networking.gossipsub.behavior import GossipsubMessageEvent
from lean_spec.subspecs.networking.gossipsub.message import GossipsubMessage
from lean_spec.subspecs.networking.gossipsub.types import TopicId

from .conftest import fast_params
from .network import GossipsubTestNetwork

TOPIC = TopicId("test/stress")


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_peer_churn(
    network: GossipsubTestNetwork,
) -> None:
    """15 nodes, remove 5, add 5 new: meshes remain valid."""

    # Nodes crash, restart, or rotate constantly in P2P networks.
    # After membership changes, heartbeat rounds must heal the mesh
    # back to valid bounds.
    params = fast_params()
    await network.create_nodes(15, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=3)

    # Remove 5 nodes to simulate sudden departures.
    removed = network.nodes[10:]
    for node in removed:
        await node.stop()

    # Remaining nodes must clean up references to departed peers.
    for node in network.nodes[:10]:
        for r in removed:
            await node.behavior.remove_peer(r.peer_id)
    network.nodes = network.nodes[:10]

    # Add 5 replacement nodes and connect them to the survivors.
    new_nodes = await network.create_nodes(5, params)
    for node in new_nodes:
        await node.start()
        node.subscribe(TOPIC)

    for new_node in new_nodes:
        for existing in network.nodes[:10]:
            await new_node.connect_to(existing)

    # Heartbeat rounds let the mesh absorb new peers via GRAFT.
    # Under CPU pressure, a fixed number of rounds may not suffice.
    # Retry until all meshes converge or a timeout is hit.
    await asyncio.sleep(0.1)
    max_rounds = 20
    for _ in range(max_rounds):
        await network.stabilize_mesh(TOPIC, rounds=1)
        if all(
            params.d_low <= node.get_mesh_size(TOPIC) <= params.d_high for node in network.nodes
        ):
            break

    for node in network.nodes:
        size = node.get_mesh_size(TOPIC)
        assert params.d_low <= size <= params.d_high, (
            f"{node.peer_id}: mesh size {size} outside [{params.d_low}, {params.d_high}]"
        )


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
    all_msg_ids = {p: GossipsubMessage.compute_id(TOPIC.encode("utf-8"), p) for p in payloads}

    await asyncio.gather(*(node.publish(TOPIC, payloads[i]) for i, node in enumerate(nodes)))

    # Each node publishes one message but does not deliver its own.
    # So each expects exactly the 4 messages from the other publishers.
    for i, node in enumerate(nodes):
        msgs = await node.wait_for_messages(4, TOPIC, timeout=10.0)
        expected_data = {payloads[j] for j in range(5) if j != i}
        assert {msg.data for msg in msgs} == expected_data, (
            f"{node.peer_id}: expected {expected_data}, got {[m.data for m in msgs]}"
        )
        for msg in msgs:
            assert msg == GossipsubMessageEvent(
                peer_id=msg.peer_id, topic=TOPIC, data=msg.data, message_id=all_msg_ids[msg.data]
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
    msg_id = GossipsubMessage.compute_id(TOPIC.encode("utf-8"), data)
    await network.nodes[0].publish(TOPIC, data)

    # All other nodes should receive the message.
    for node in network.nodes[1:]:
        msg = await node.wait_for_message(TOPIC, timeout=10.0)
        assert msg == GossipsubMessageEvent(
            peer_id=msg.peer_id, topic=TOPIC, data=data, message_id=msg_id
        )
