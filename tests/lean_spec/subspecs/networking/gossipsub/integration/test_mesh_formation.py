"""Mesh formation with multiple peers.

Gossipsub controls mesh size with three parameters:

- D: target mesh degree (desired number of mesh peers)
- D_low: lower bound -- below this, heartbeat GRAFTs new peers
- D_high: upper bound -- above this, heartbeat PRUNEs excess peers

Each heartbeat round moves every node's mesh closer to [D_low, D_high].
Multiple rounds are needed because GRAFT/PRUNE propagation is async
and one node's change can ripple through the network.
"""

from __future__ import annotations

import asyncio

import pytest

from lean_spec.subspecs.networking.gossipsub.types import TopicId

from .conftest import fast_params
from .network import GossipsubTestNetwork

TOPIC = TopicId("test/mesh")


def _all_meshes_in_bounds(network: GossipsubTestNetwork, params, topic: str) -> bool:  # type: ignore[no-untyped-def]
    """Check whether every node's mesh is within [D_low, D_high]."""
    return all(params.d_low <= node.get_mesh_size(topic) <= params.d_high for node in network.nodes)


@pytest.mark.asyncio
async def test_mesh_forms_within_d_parameters(
    network: GossipsubTestNetwork,
) -> None:
    """10 nodes: each mesh converges to D_low <= size <= D_high."""

    # Disable automatic heartbeat so meshes stay empty until we trigger manually.
    params = fast_params(heartbeat_interval_secs=999)
    await network.create_nodes(10, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)

    # Precondition: meshes are out of bounds (all empty, below D_low).
    assert not _all_meshes_in_bounds(network, params, TOPIC)

    # Multiple heartbeat rounds let GRAFT/PRUNE RPCs propagate.
    # Each round, nodes detect under/over-sized meshes and correct.
    await network.stabilize_mesh(TOPIC, rounds=5)

    # Postcondition: all meshes converged to [D_low, D_high].
    for node in network.nodes:
        size = node.get_mesh_size(TOPIC)
        assert params.d_low <= size <= params.d_high, (
            f"{node.peer_id}: mesh size {size} outside [{params.d_low}, {params.d_high}]"
        )


@pytest.mark.asyncio
async def test_mesh_rebalances_after_new_peers(
    network: GossipsubTestNetwork,
) -> None:
    """Adding new peers keeps meshes within bounds after rebalancing."""

    # Disable automatic heartbeat so mesh state only changes via manual triggers.
    params = fast_params(heartbeat_interval_secs=999)
    initial = await network.create_nodes(5, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=3)

    # Add 5 more peers and connect them.
    new_nodes = await network.create_nodes(5, params)
    for node in new_nodes:
        await node.start()
        node.subscribe(TOPIC)

    # Connect new nodes to existing ones and to each other.
    for new_node in new_nodes:
        for existing in initial:
            await new_node.connect_to(existing)
    for i, a in enumerate(new_nodes):
        for b in new_nodes[i + 1 :]:
            await a.connect_to(b)

    await asyncio.sleep(0.1)

    # Precondition: new nodes have empty meshes (below D_low), so the
    # network as a whole is out of bounds.
    assert not _all_meshes_in_bounds(network, params, TOPIC)

    # Rebalancing: heartbeats detect out-of-bounds meshes and correct
    # via GRAFT (too few peers) and PRUNE (too many peers).
    await network.stabilize_mesh(TOPIC, rounds=5)

    # Postcondition: all meshes converged to [D_low, D_high].
    for node in network.nodes:
        size = node.get_mesh_size(TOPIC)
        assert params.d_low <= size <= params.d_high, (
            f"{node.peer_id}: mesh size {size} outside [{params.d_low}, {params.d_high}]"
        )
