"""
Assertion helpers for interop tests.

Provides async-friendly assertions for consensus state verification.
"""

from __future__ import annotations

import asyncio
import logging
import time

from lean_spec.types import Bytes32

from .node_runner import NodeCluster, TestNode

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

        if not head_slots:
            await asyncio.sleep(0.5)
            continue

        min_slot = min(head_slots)
        max_slot = max(head_slots)

        if max_slot - min_slot <= max_slot_diff:
            logger.debug("Heads consistent: slots %s", head_slots)
            return

        await asyncio.sleep(0.5)

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

        if all(count >= min_peers for count in peer_counts):
            logger.debug("Peer connections satisfied: %s (min: %d)", peer_counts, min_peers)
            return

        await asyncio.sleep(0.5)

    peer_counts = [node.peer_count for node in cluster.nodes]
    raise AssertionError(
        f"Peer connection timeout: counts {peer_counts}, required minimum {min_peers}"
    )


async def assert_block_propagated(
    cluster: NodeCluster,
    block_root: Bytes32,
    timeout: float = 10.0,
    poll_interval: float = 0.2,
) -> None:
    """
    Assert a block propagates to all nodes.

    Args:
        cluster: Node cluster to check.
        block_root: Root of the block to check for.
        timeout: Maximum wait time.
        poll_interval: Time between checks.

    Raises:
        AssertionError: If block not found on all nodes within timeout.
    """
    start = time.monotonic()

    while time.monotonic() - start < timeout:
        found = [block_root in node.node.store.blocks for node in cluster.nodes]

        if all(found):
            logger.debug("Block %s propagated to all nodes", block_root.hex()[:8])
            return

        await asyncio.sleep(poll_interval)

    found = [block_root in node.node.store.blocks for node in cluster.nodes]
    raise AssertionError(
        f"Block propagation timeout: {block_root.hex()[:8]} found on nodes {found}"
    )


async def assert_same_finalized_checkpoint(
    nodes: list[TestNode],
    timeout: float = 30.0,
) -> None:
    """
    Assert all nodes agree on the finalized checkpoint.

    Args:
        nodes: List of nodes to check.
        timeout: Maximum wait time.

    Raises:
        AssertionError: If nodes disagree on finalized checkpoint.
    """
    start = time.monotonic()

    while time.monotonic() - start < timeout:
        checkpoints = [
            (node.node.store.latest_finalized.slot, node.node.store.latest_finalized.root)
            for node in nodes
        ]

        if len(set(checkpoints)) == 1:
            slot, root = checkpoints[0]
            logger.debug(
                "All nodes agree on finalized checkpoint: slot=%d, root=%s",
                slot,
                root.hex()[:8],
            )
            return

        await asyncio.sleep(0.5)

    checkpoints = []
    for node in nodes:
        slot = int(node.node.store.latest_finalized.slot)
        root_hex = node.node.store.latest_finalized.root.hex()[:8]
        checkpoints.append((slot, root_hex))
    raise AssertionError(f"Finalized checkpoint disagreement: {checkpoints}")


async def assert_chain_progressing(
    cluster: NodeCluster,
    duration: float = 20.0,
    min_slot_increase: int = 2,
) -> None:
    """
    Assert the chain is making progress.

    Args:
        cluster: Node cluster to check.
        duration: Time to observe progress.
        min_slot_increase: Minimum slot increase expected.

    Raises:
        AssertionError: If chain doesn't progress as expected.
    """
    if not cluster.nodes:
        raise AssertionError("No nodes in cluster")

    initial_slots = [node.head_slot for node in cluster.nodes]
    await asyncio.sleep(duration)
    final_slots = [node.head_slot for node in cluster.nodes]

    increases = [final - initial for initial, final in zip(initial_slots, final_slots, strict=True)]

    if not all(inc >= min_slot_increase for inc in increases):
        raise AssertionError(
            f"Chain not progressing: slot increases {increases}, "
            f"expected at least {min_slot_increase}"
        )

    logger.debug("Chain progressing: slot increases %s", increases)
