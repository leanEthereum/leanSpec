"""Subscription lifecycle tests."""

from __future__ import annotations

import asyncio

import pytest

from lean_spec.node.networking.gossipsub.types import TopicId
from tests.integration.networking.gossipsub.conftest import fast_params
from tests.integration.networking.gossipsub.network import GossipsubTestNetwork

TOPIC = TopicId("test/subscription")


@pytest.mark.asyncio
async def test_subscribe_forms_mesh(
    network: GossipsubTestNetwork,
) -> None:
    """After subscribing and heartbeats, mesh size is > 0."""
    params = fast_params()
    nodes = await network.create_nodes(4, params)
    await network.start_all()
    await network.connect_full()

    # Subscribing registers interest but does not create mesh links yet.
    await network.subscribe_all(TOPIC)

    # Heartbeats are where mesh formation actually happens.
    # Each node picks D peers to GRAFT into its mesh.
    await network.stabilize_mesh(TOPIC, rounds=3)

    for node in nodes:
        assert node.get_mesh_size(TOPIC) > 0, f"{node.peer_id}: empty mesh after subscribe"


@pytest.mark.asyncio
async def test_unsubscribe_sends_prune(
    network: GossipsubTestNetwork,
) -> None:
    """After unsubscribing, the node is removed from peers' meshes."""
    params = fast_params()
    nodes = await network.create_nodes(4, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=3)

    # Unsubscribing sends PRUNE to all mesh peers for this topic.
    # Each PRUNE tells the peer: "remove me from your mesh."
    leaver = nodes[0]
    leaver.unsubscribe(TOPIC)
    await asyncio.sleep(0.2)

    # Trigger heartbeats so peers process PRUNE.
    await network.trigger_all_heartbeats()
    await asyncio.sleep(0.1)

    # No other node should have the leaver in their mesh.
    for node in nodes[1:]:
        mesh_peers = node.get_mesh_peers(TOPIC)
        assert leaver.peer_id not in mesh_peers, (
            f"{node.peer_id} still has {leaver.peer_id} in mesh after unsubscribe"
        )


@pytest.mark.asyncio
async def test_late_join_fills_mesh(
    network: GossipsubTestNetwork,
) -> None:
    """A node subscribing after initial formation gets grafted into the mesh."""
    params = fast_params()
    nodes = await network.create_nodes(5, params)
    await network.start_all()
    await network.connect_full()

    # Only first 4 subscribe initially.
    for node in nodes[:4]:
        node.subscribe(TOPIC)
    await asyncio.sleep(0.1)
    await network.stabilize_mesh(TOPIC, rounds=3)

    # The late joiner subscribes after the mesh already formed.
    # It has no mesh peers yet -- just a subscription announcement.
    late = nodes[4]
    late.subscribe(TOPIC)
    await asyncio.sleep(0.1)

    # Heartbeat rounds let the late joiner GRAFT into the mesh
    # and let existing nodes discover and GRAFT the newcomer.
    await network.stabilize_mesh(TOPIC, rounds=3)

    assert late.get_mesh_size(TOPIC) > 0, "Late joiner has empty mesh"


@pytest.mark.asyncio
async def test_resubscribe_reforms_mesh(
    network: GossipsubTestNetwork,
) -> None:
    """Unsubscribing then resubscribing reforms the mesh correctly."""
    params = fast_params()
    nodes = await network.create_nodes(4, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=3)

    target = nodes[0]

    # Unsubscribe.
    target.unsubscribe(TOPIC)
    await asyncio.sleep(0.2)
    await network.trigger_all_heartbeats()
    await asyncio.sleep(0.1)

    assert target.get_mesh_size(TOPIC) == 0

    # PRUNE includes a 60-second backoff timer.
    # During backoff, a peer rejects GRAFT from the pruned node.
    # Clear backoff manually so resubscription works immediately.
    for node in nodes:
        for peer_state in node.behavior._peers.values():
            peer_state.backoff.clear()

    # Resubscribe.
    target.subscribe(TOPIC)
    await asyncio.sleep(0.2)
    await network.stabilize_mesh(TOPIC, rounds=5)

    assert target.get_mesh_size(TOPIC) > 0, "Mesh did not reform after resubscribe"
