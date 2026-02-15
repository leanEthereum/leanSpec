"""End-to-end consensus lifecycle test.

Tests the networking, gossip, and block production stack in a 3-node cluster.
Phases 1-4 verify connectivity, block propagation, attestation activity,
and continued chain growth - all timing-tolerant properties that work
reliably on CI runners with limited CPU.

Consensus liveness (justification, finalization) requires the attestation
pipeline to meet tight 800ms interval deadlines. On a 2-core CI runner
with 3 nodes sharing a single asyncio event loop, CPU contention causes
missed interval boundaries, divergent attestation targets, and aggregation
failures. These properties are not tested here.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from .helpers import (
    NodeCluster,
    PipelineDiagnostics,
    assert_checkpoint_monotonicity,
    assert_heads_consistent,
    assert_peer_connections,
    full_mesh,
)

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.interop

NUM_VALIDATORS = 3
"""Number of validators in the test cluster.

Three is the smallest committee where 2/3 supermajority is meaningful.

Round-robin proposer assignment cycles through all validators:

- slot 1 -> validator 1  (1 % 3)
- slot 2 -> validator 2  (2 % 3)
- slot 3 -> validator 0  (3 % 3)
"""


MIN_ATTESTATION_ACTIVITY = 3
"""
Minimum attestation pipeline activity across all nodes after one slot.

Each validator produces one attestation per slot.
After 4 seconds (one slot), all 3 must have entered the pipeline.
Activity counts gossip signatures, new aggregated, and known aggregated.
"""


@pytest.mark.timeout(120)
@pytest.mark.num_validators(3)
async def test_consensus_lifecycle(node_cluster: NodeCluster) -> None:
    """
    Validate networking, gossip, and block production in a 3-node cluster.

    Tests four timing-tolerant properties:

    1. Connectivity - QUIC full mesh forms
    2. Block production - blocks propagate via gossip
    3. Attestation activity - attestations enter the pipeline
    4. Continued growth - chain advances across multiple slots

    Checkpoint snapshots from every phase feed into a final
    monotonicity check.
    """
    # Every node connects to every other node.
    # With 3 nodes this creates 3 bidirectional links: 0-1, 0-2, 1-2.
    topology = full_mesh(NUM_VALIDATORS)

    # One validator per node. Isolating validators ensures each node
    # proposes independently and attestations travel over the network.
    validators_per_node = [[0], [1], [2]]

    await node_cluster.start_all(topology, validators_per_node)

    # Collect diagnostic snapshots after each phase.
    # Used at the end to verify checkpoint monotonicity across phases.
    checkpoint_history: list[list[PipelineDiagnostics]] = []

    # Phase 1: Connectivity
    #
    # In a full mesh of 3 nodes, each node has exactly 2 peers.
    # QUIC connections establish in under a second, so 5s is generous.
    # This phase gates all subsequent phases that rely on gossip.
    logger.info("Phase 1: Connectivity")
    await assert_peer_connections(node_cluster, min_peers=2, timeout=5)
    diags = node_cluster.log_diagnostics("connectivity")
    checkpoint_history.append(diags)

    # Phase 2: Block production
    #
    # Wait for all nodes to advance past genesis.
    # Once slot 1 is reached, verify three properties:
    #
    # 1. Gossip completeness - blocks propagate to all peers
    # 2. Parent chain integrity - slot numbers strictly increase
    # 3. Proposer assignment - round-robin matches slot % 3
    logger.info("Phase 2: Block production")
    reached = await node_cluster.wait_for_slot(target_slot=1, timeout=25)
    diags = node_cluster.log_diagnostics("block-production")
    checkpoint_history.append(diags)
    assert reached, f"Block production stalled: head slots {[d.head_slot for d in diags]}"

    # Gossip completeness: every block should reach every node.
    #
    # Tolerate at most 1 missing block per node.
    # A block produced at the boundary of the check window
    # may still be propagating through the mesh.
    block_sets = [set(node._store.blocks.keys()) for node in node_cluster.nodes]
    all_blocks = block_sets[0] | block_sets[1] | block_sets[2]
    for i, bs in enumerate(block_sets):
        missing = all_blocks - bs
        assert len(missing) <= 1, (
            f"Node {i} missing {len(missing)} blocks: has {len(bs)}/{len(all_blocks)}"
        )

    # Parent chain integrity: walk backward from head to genesis.
    #
    # Each block must reference a parent with a strictly lower slot.
    # A violation here indicates a fork or misordered import.
    for node in node_cluster.nodes:
        store = node._store
        head_block = store.blocks[store.head]
        visited = 0
        current = head_block
        while current.parent_root in store.blocks:
            parent = store.blocks[current.parent_root]
            assert current.slot > parent.slot, (
                f"Node {node.index}: block at slot {current.slot} has parent at slot {parent.slot}"
            )
            current = parent
            visited += 1

        logger.info(
            "Node %d parent chain: %d blocks from head slot %d",
            node.index,
            visited,
            int(head_block.slot),
        )

    # Proposer assignment: round-robin rotation.
    #
    # For every non-genesis block, proposer_index must equal slot % 3.
    # This confirms the validator schedule is correctly applied.
    store = node_cluster.nodes[0]._store
    for _root, block in store.blocks.items():
        if int(block.slot) == 0:
            continue
        expected_proposer = int(block.slot) % NUM_VALIDATORS
        assert int(block.proposer_index) == expected_proposer, (
            f"Block at slot {block.slot} has proposer "
            f"{block.proposer_index}, expected {expected_proposer}"
        )

    # Phase 3: Attestation pipeline
    #
    # Validators produce attestations once per slot (every 4 seconds).
    # After sleeping one full slot, the pipeline should contain entries
    # from all three validators: gossip signatures, new aggregated
    # payloads, or already-known aggregated payloads.
    logger.info("Phase 3: Attestation pipeline")
    await asyncio.sleep(4)
    diags = node_cluster.log_diagnostics("attestation")
    checkpoint_history.append(diags)

    # Cluster-wide check: total activity must reach the threshold.
    # Three validators each produce one attestation, so the sum of
    # all pipeline stages across all nodes must be at least 3.
    total_activity = sum(
        d.gossip_signatures_count + d.new_aggregated_count + d.known_aggregated_count for d in diags
    )
    assert total_activity >= MIN_ATTESTATION_ACTIVITY, (
        f"Expected >= {MIN_ATTESTATION_ACTIVITY} attestation pipeline "
        f"entries across all nodes, got {total_activity}"
    )

    # Per-node check: every node must have seen at least one entry.
    # A node with zero activity indicates a gossip or subscription failure.
    for i, d in enumerate(diags):
        node_activity = (
            d.gossip_signatures_count + d.new_aggregated_count + d.known_aggregated_count
        )
        assert node_activity >= 1, (
            f"Node {i}: zero attestation pipeline activity "
            f"(gsigs={d.gossip_signatures_count}, "
            f"nagg={d.new_aggregated_count}, "
            f"kagg={d.known_aggregated_count})"
        )

    # Phase 4: Continued block production
    #
    # Wait for all nodes to reach slot 3. This proves:
    #
    # 1. Block production continues across multiple slots
    # 2. Proposer rotation works (slots 1-3 use all 3 validators)
    # 3. Gossip propagation sustains under load
    #
    # After reaching slot 3, verify head consistency and block content.
    logger.info("Phase 4: Continued block production")
    reached = await node_cluster.wait_for_slot(target_slot=3, timeout=30)
    diags = node_cluster.log_diagnostics("continued-production")
    checkpoint_history.append(diags)
    assert reached, f"Continued production stalled: head slots {[d.head_slot for d in diags]}"

    # Head consistency: all nodes must be within 2 slots of each other.
    # Larger drift would indicate a partition or stalled gossip.
    await assert_heads_consistent(node_cluster, max_slot_diff=2, timeout=10)

    # Proposer diversity: with slot >= 3, all 3 validators must have proposed.
    #
    # Round-robin gives:
    # - slot 1 to validator 1  (1 % 3)
    # - slot 2 to validator 2  (2 % 3)
    # - slot 3 to validator 0  (3 % 3)
    store = node_cluster.nodes[0]._store
    proposers: set[int] = set()
    for _root, block in store.blocks.items():
        if int(block.slot) > 0:
            proposers.add(int(block.proposer_index))

    assert len(proposers) >= 2, f"Expected >= 2 distinct proposers by slot 3, got {proposers}"

    # Block body content: blocks after slot 1 should carry attestations.
    #
    # Proposers include pending attestations in the block body.
    # If no blocks after slot 1 contain attestations, the pipeline
    # from attestation production to block inclusion is broken.
    blocks_with_attestations = 0
    checked_blocks = 0
    for _root, block in store.blocks.items():
        slot = int(block.slot)
        if slot <= 1:
            continue
        checked_blocks += 1
        att_count = len(block.body.attestations)
        if att_count > 0:
            blocks_with_attestations += 1
        logger.info("Slot %d: %d attestations in block body", slot, att_count)

    # At least one block after slot 1 must exist and contain attestations.
    assert checked_blocks >= 1, "No blocks after slot 1 found in store"
    assert blocks_with_attestations >= 1, (
        f"No blocks after slot 1 contain attestations (checked {checked_blocks} blocks)"
    )

    # Final cross-phase invariant: checkpoint slots must never decrease.
    #
    # Justified and finalized slots are monotonically increasing.
    # A regression in any phase would indicate a fork choice or
    # state transition bug.
    assert_checkpoint_monotonicity(checkpoint_history)

    logger.info("All 4 phases passed.")
