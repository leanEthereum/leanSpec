"""
Late joiner and checkpoint sync tests.

Tests verify that nodes joining late can sync up with
the existing chain state.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from .helpers import (
    NodeCluster,
    assert_all_finalized_to,
    assert_heads_consistent,
    assert_peer_connections,
)

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.interop


@pytest.mark.skip(reason="Interop test not passing - needs update (#359)")
@pytest.mark.timeout(240)
@pytest.mark.num_validators(3)
async def test_late_joiner_sync(node_cluster: NodeCluster) -> None:
    """
    Late joining node syncs to finalized chain.

    Two nodes start and finalize some slots. A third node
    joins late and should sync up to the current state.
    """
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_node(0, validators_per_node[0])
    await node_cluster.start_node(1, validators_per_node[1])

    node0 = node_cluster.nodes[0]
    node1 = node_cluster.nodes[1]

    await asyncio.sleep(1)
    await node0.dial(node1.listen_addr)

    await assert_peer_connections(node_cluster, min_peers=1, timeout=30)

    logger.info("Waiting for initial finalization before late joiner...")
    await assert_all_finalized_to(node_cluster, target_slot=4, timeout=90)

    initial_finalized = node0.finalized_slot
    logger.info("Initial finalization at slot %d, starting late joiner", initial_finalized)

    addr0 = node_cluster.get_multiaddr(0)
    addr1 = node_cluster.get_multiaddr(1)

    late_node = await node_cluster.start_node(2, validators_per_node[2], bootnodes=[addr0, addr1])

    await asyncio.sleep(30)

    late_slot = late_node.head_slot
    logger.info("Late joiner head slot: %d", late_slot)

    assert late_slot >= initial_finalized, (
        f"Late joiner should sync to at least {initial_finalized}, got {late_slot}"
    )

    await assert_heads_consistent(node_cluster, max_slot_diff=3, timeout=30)


@pytest.mark.timeout(120)
@pytest.mark.num_validators(4)
async def test_multiple_late_joiners(node_cluster: NodeCluster) -> None:
    """
    Multiple nodes join at different times.

    Tests that the network handles multiple late joiners gracefully.
    """
    validators_per_node = [[0], [1], [2], [3]]

    await node_cluster.start_node(0, validators_per_node[0])
    await asyncio.sleep(5)

    addr0 = node_cluster.get_multiaddr(0)
    await node_cluster.start_node(1, validators_per_node[1], bootnodes=[addr0])

    await asyncio.sleep(10)

    addr1 = node_cluster.get_multiaddr(1)
    await node_cluster.start_node(2, validators_per_node[2], bootnodes=[addr0, addr1])

    await asyncio.sleep(10)

    addr2 = node_cluster.get_multiaddr(2)
    await node_cluster.start_node(3, validators_per_node[3], bootnodes=[addr0, addr2])

    await assert_peer_connections(node_cluster, min_peers=1, timeout=30)

    await assert_heads_consistent(node_cluster, max_slot_diff=3, timeout=60)

    head_slots = [n.head_slot for n in node_cluster.nodes]
    logger.info("Final head slots: %s", head_slots)

    min_head = min(head_slots)
    max_head = max(head_slots)
    assert max_head - min_head <= 3, f"Head divergence too large: {head_slots}"
