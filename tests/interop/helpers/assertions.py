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

from .diagnostics import PipelineDiagnostics
from .node_runner import NodeCluster

logger = logging.getLogger(__name__)


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

    for node_index in range(num_nodes):
        previous_justified = 0
        previous_finalized = 0
        for phase_index, phase_diags in enumerate(checkpoint_history):
            d = phase_diags[node_index]
            assert d.justified_slot >= previous_justified, (
                f"Node {node_index} justified_slot regressed: "
                f"{previous_justified} -> {d.justified_slot} at phase {phase_index}"
            )
            assert d.finalized_slot >= previous_finalized, (
                f"Node {node_index} finalized_slot regressed: "
                f"{previous_finalized} -> {d.finalized_slot} at phase {phase_index}"
            )
            previous_justified = d.justified_slot
            previous_finalized = d.finalized_slot
