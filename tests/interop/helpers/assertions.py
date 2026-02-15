"""
Assertion helpers for interop tests.

Provides async-friendly assertions for consensus state verification.
Each polling helper reads node state until a condition is met or a timeout expires.
Synchronous helpers verify structural invariants on the current state.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Literal

from .diagnostics import PipelineDiagnostics
from .node_runner import NodeCluster

logger = logging.getLogger(__name__)


async def assert_all_finalized_to(
    cluster: NodeCluster,
    target_slot: int,
    timeout: float = 120.0,
) -> None:
    """
    Assert all nodes finalize to at least target_slot.

    Args:
        cluster: Node cluster to check.
        target_slot: Minimum finalized slot required.
        timeout: Maximum wait time in seconds.

    Raises:
        AssertionError: If timeout reached before finalization.
    """
    success = await cluster.wait_for_finalization(target_slot, timeout)
    if not success:
        slots = [node.finalized_slot for node in cluster.nodes]
        raise AssertionError(
            f"Finalization timeout: expected slot >= {target_slot}, got finalized slots {slots}"
        )


async def assert_heads_consistent(
    cluster: NodeCluster,
    max_slot_diff: int = 1,
    timeout: float = 30.0,
) -> None:
    """
    Assert all nodes have consistent head slots.

    Allows small differences due to propagation delay.

    Args:
        cluster: Node cluster to check.
        max_slot_diff: Maximum allowed slot difference between nodes.
        timeout: Maximum wait time for consistency.

    Raises:
        AssertionError: If heads diverge more than allowed.
    """
    start = time.monotonic()

    while time.monotonic() - start < timeout:
        head_slots = [node.head_slot for node in cluster.nodes]

        # Skip empty clusters (no nodes started yet).
        if not head_slots:
            await asyncio.sleep(0.5)
            continue

        min_slot = min(head_slots)
        max_slot = max(head_slots)

        # All nodes within the allowed divergence window.
        if max_slot - min_slot <= max_slot_diff:
            logger.debug("Heads consistent: slots %s", head_slots)
            return

        await asyncio.sleep(0.5)

    # Final read after timeout for the error message.
    head_slots = [node.head_slot for node in cluster.nodes]
    raise AssertionError(
        f"Head consistency timeout: slots {head_slots} differ by more than {max_slot_diff}"
    )


async def assert_peer_connections(
    cluster: NodeCluster,
    min_peers: int = 1,
    timeout: float = 30.0,
) -> None:
    """
    Assert all nodes have minimum peer connections.

    Args:
        cluster: Node cluster to check.
        min_peers: Minimum required peer count per node.
        timeout: Maximum wait time.

    Raises:
        AssertionError: If any node has fewer peers than required.
    """
    start = time.monotonic()

    while time.monotonic() - start < timeout:
        peer_counts = [node.peer_count for node in cluster.nodes]

        # Every node must meet the minimum before we return success.
        if all(count >= min_peers for count in peer_counts):
            logger.debug("Peer connections satisfied: %s (min: %d)", peer_counts, min_peers)
            return

        await asyncio.sleep(0.5)

    # Final read after timeout for the error message.
    peer_counts = [node.peer_count for node in cluster.nodes]
    raise AssertionError(
        f"Peer connection timeout: counts {peer_counts}, required minimum {min_peers}"
    )


async def assert_same_finalized_checkpoint(
    cluster: NodeCluster,
    timeout: float = 30.0,
) -> None:
    """
    Assert all nodes agree on the finalized checkpoint.

    Args:
        cluster: Node cluster to check.
        timeout: Maximum wait time.

    Raises:
        AssertionError: If nodes disagree on finalized checkpoint.
    """
    start = time.monotonic()

    while time.monotonic() - start < timeout:
        # Compare (slot, root) tuples.
        # Tuples are hashable, so deduplication via set detects disagreement.
        checkpoints = [
            (node.node.store.latest_finalized.slot, node.node.store.latest_finalized.root)
            for node in cluster.nodes
        ]

        # All nodes agree when there is exactly one unique checkpoint.
        if len(set(checkpoints)) == 1:
            slot, root = checkpoints[0]
            logger.debug(
                "All nodes agree on finalized checkpoint: slot=%d, root=%s",
                slot,
                root.hex()[:8],
            )
            return

        await asyncio.sleep(0.5)

    # Build a readable summary for the error message.
    checkpoints_summary = []
    for node in cluster.nodes:
        slot = int(node.node.store.latest_finalized.slot)
        root_hex = node.node.store.latest_finalized.root.hex()[:8]
        checkpoints_summary.append((slot, root_hex))
    raise AssertionError(f"Finalized checkpoint disagreement: {checkpoints_summary}")


def assert_head_descends_from(
    cluster: NodeCluster,
    checkpoint: Literal["finalized", "justified"],
) -> None:
    """
    Verify the fork choice invariant: head must descend from a checkpoint.

    The fork choice algorithm starts from the checkpoint root and walks
    forward. If head is not a descendant, the algorithm is broken.

    Walks backward from head toward genesis on each node.
    The checkpoint root must appear on this path.

    Args:
        cluster: Node cluster to check.
        checkpoint: Which checkpoint to verify ancestry against.

    Raises:
        AssertionError: If any node's head is not a descendant of the checkpoint.
    """
    for node in cluster.nodes:
        store = node._store

        cp = store.latest_finalized if checkpoint == "finalized" else store.latest_justified
        cp_root = cp.root
        cp_slot = int(cp.slot)

        # Walk backward from head toward genesis.
        # The checkpoint root must appear on this path.
        current_root = store.head
        found = False
        while current_root in store.blocks:
            if current_root == cp_root:
                found = True
                break
            block = store.blocks[current_root]
            # Reached genesis without finding the checkpoint.
            if int(block.slot) == 0:
                break
            current_root = block.parent_root

        assert found, (
            f"Node {node.index}: head {store.head.hex()[:8]} is not a descendant "
            f"of {checkpoint} root {cp_root.hex()[:8]} at slot {cp_slot}"
        )


def assert_checkpoint_monotonicity(
    checkpoint_history: list[list[PipelineDiagnostics]],
) -> None:
    """
    Verify checkpoint slots never decrease across test phases.

    A regression in justified or finalized slot would indicate
    a fork choice or state transition bug. Checks every node
    independently across the ordered sequence of phase snapshots.

    Args:
        checkpoint_history: Diagnostics snapshots from each phase, in order.

    Raises:
        AssertionError: If any node's checkpoint slot decreased between phases.
    """
    if not checkpoint_history:
        return

    num_nodes = len(checkpoint_history[0])

    for node_idx in range(num_nodes):
        prev_justified = 0
        prev_finalized = 0
        for phase_idx, phase_diags in enumerate(checkpoint_history):
            d = phase_diags[node_idx]
            assert d.justified_slot >= prev_justified, (
                f"Node {node_idx} justified_slot regressed: "
                f"{prev_justified} -> {d.justified_slot} at phase {phase_idx}"
            )
            assert d.finalized_slot >= prev_finalized, (
                f"Node {node_idx} finalized_slot regressed: "
                f"{prev_finalized} -> {d.finalized_slot} at phase {phase_idx}"
            )
            prev_justified = d.justified_slot
            prev_finalized = d.finalized_slot
