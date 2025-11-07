"""Fork Choice Head Selection (LMD-GHOST Algorithm)"""

import pytest
from consensus_testing import (
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)

from lean_spec.subspecs.containers.slot import Slot

pytestmark = pytest.mark.valid_until("Devnet")


def test_head_advances_through_deep_chain(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Fork choice head advances through a deep chain correctly.

    Scenario
    --------
    Build a long chain (slots 1-20) and verify head reaches the end.

    Expected Behavior:
        - Head advances through all 20 blocks
        - Final head = slot 20
        - Fork choice scales to longer chains

    Why This Matters
    ----------------
    This tests that the fork choice algorithm scales to longer chains and
    correctly handles the tree-walking logic through many blocks.

    Real networks have chains thousands of blocks long. The algorithm must:
    - Efficiently traverse deep trees
    - Maintain correct head even with many ancestors
    - Not degrade in performance or correctness with depth

    A 20-block chain is a modest test of this scalability.
    """
    steps = []
    for i in range(1, 21):
        # Add label to last block so we can verify root
        if i == 20:
            steps.append(
                BlockStep(
                    block=BlockSpec(slot=Slot(i), label="block_20"),
                    checks=StoreChecks(
                        head_slot=Slot(i),
                        head_root_label="block_20",
                    ),
                )
            )
        else:
            steps.append(
                BlockStep(
                    block=BlockSpec(slot=Slot(i)),
                    checks=StoreChecks(head_slot=Slot(i)),
                )
            )

    fork_choice_test(steps=steps)


def test_head_with_gaps_in_slots(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Fork choice head handles missing slots correctly.

    Scenario
    --------
    Build blocks at slots 1, 3, 5, 7, 9 (skipping even slots).

    Expected Behavior:
        - Head advances to each present block
        - Skipped slots don't affect fork choice
        - Head correctly identifies the leaf despite gaps

    Why This Matters
    ----------------
    Missed slots are common in production:
    - Offline proposers
    - Network partitions
    - Proposer failures

    Fork choice must handle sparse block production correctly. The algorithm
    doesn't require consecutive slots - it works with any tree structure where
    gaps are simply missing nodes.

    This verifies the algorithm handles real-world conditions where not every
    slot has a block, which is the norm rather than the exception.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),  # Skip slot 2
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),  # Skip slot 4
                checks=StoreChecks(head_slot=Slot(5)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7)),  # Skip slot 6
                checks=StoreChecks(head_slot=Slot(7)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(9)),  # Skip slot 8
                checks=StoreChecks(head_slot=Slot(9)),
            ),
        ],
    )


def test_head_with_large_gaps(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Fork choice head handles large gaps between blocks.

    Scenario
    --------
    Build blocks at slots 1, 10, 20, 30 (gaps of 9-10 slots).

    Expected Behavior:
        - Head advances despite large gaps
        - Fork choice is gap-size independent
        - Head reaches the furthest block

    Why This Matters
    ----------------
    Large gaps can occur during:
    - Extended network partitions
    - Chain reorganizations
    - Periods of high validator downtime
    - Initial sync after being offline

    The fork choice algorithm must remain correct regardless of gap size.
    Distance between blocks should not affect the correctness of head selection -
    only the tree structure matters.

    This test verifies that even with dramatic gaps (representing severe network
    conditions), fork choice still identifies the correct head.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(10)),
                checks=StoreChecks(head_slot=Slot(10)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(20)),
                checks=StoreChecks(head_slot=Slot(20)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(30)),
                checks=StoreChecks(head_slot=Slot(30)),
            ),
        ],
    )


def test_head_with_two_competing_forks(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Fork choice selects head when two forks compete at the same slot.

    Scenario
    --------
    Create two competing blocks at slot 2, both building on slot 1.

    Expected Behavior:
        - After slot 1: head = slot 1 (common ancestor)
        - After fork A (slot 2): head = slot 2 (fork A, first seen)
        - After fork B (slot 2): head = slot 2 (still fork A)
        - Both forks have equal weight (1 proposer attestation each)
        - Head breaks tie lexicographically by block root

    Why This Matters
    ----------------
    This is an important fork choice scenario: two blocks competing for the
    same slot. Even with equal attestation weight, fork choice must deterministically
    select a head.

    The algorithm uses lexicographic order of block roots as a tie-breaker,
    ensuring all nodes agree on the same head even when forks have equal weight.

    This prevents network splits and ensures consensus converges.
    """
    fork_choice_test(
        steps=[
            # Common ancestor
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="common"),
            ),
            # Fork A at slot 2
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="common",
                    label="fork_a",
                ),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a"),
            ),
            # Competing fork B at slot 2
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="common",  # Same parent
                    label="fork_b",
                ),
                # Head determined by tie-breaker (lexicographic root order)
                # The tie is broken by comparing block roots lexicographically
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a"),
            ),
        ],
    )


def test_head_switches_to_heavier_fork(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Fork choice head switches when a competing fork becomes heavier.

    Scenario
    --------
    Create two forks at slot 2, then extend one fork to make it heavier.

    Expected Behavior:
        - After fork A (slot 2): head = fork A
        - After fork B (slot 2): head = still fork A (tie-breaker)
        - After extending fork B (slot 3): head = slot 3 (fork B wins!)

    Why This Matters
    ----------------
    This demonstrates the core LMD-GHOST property: the head follows the heaviest
    subtree. When fork B is extended with a child block, that child's proposer
    implicitly attests to fork B, giving it more weight.

    Fork choice recognizes this weight increase and switches the head to fork B's
    descendant. This is how the protocol reaches consensus - validators converge
    on the fork with the most support (weight).

    This is also how reorgs happen: a previously non-canonical fork can become
    canonical if it gains more attestation weight.
    """
    fork_choice_test(
        steps=[
            # Common ancestor
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="common"),
            ),
            # Fork A at slot 2
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="common",
                    label="fork_a",
                ),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a"),
            ),
            # Competing fork B at slot 2
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="common",
                    label="fork_b",
                ),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a"),
            ),
            # Extend fork B - gives it more weight
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="fork_b",  # Build on fork B
                    label="fork_b_3",
                ),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="fork_b_3"),
            ),
        ],
    )


def test_head_with_deep_fork_split(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Fork choice handles deep fork splits correctly.

    Scenario
    --------
    Create two forks that diverge at slot 2 and extend to different depths.

    Expected Behavior:
        - Fork A extends to slot 4
        - Fork B extends to slot 5
        - Head follows the longer (heavier) fork B

    Why This Matters
    ----------------
    In practice, forks can persist for multiple slots before one gains dominance.
    This tests that fork choice correctly follows the deeper fork, which has
    accumulated more proposer attestations along its chain.

    Each block in a fork adds weight from its proposer's attestation. A longer
    fork has more accumulated weight from the proposers along its length.

    This is how the protocol ensures liveness: the chain that continues to grow
    (accumulating blocks and attestations) becomes the canonical chain.
    """
    fork_choice_test(
        steps=[
            # Common ancestor
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="common"),
            ),
            # Fork A: slots 2, 3, 4
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="common", label="fork_a_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a_2"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_a_2", label="fork_a_3"),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="fork_a_3"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_a_3", label="fork_a_4"),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_a_4"),
            ),
            # Fork B: slots 2, 3, 4, 5 (longer)
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="common", label="fork_b_2"),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_a_4"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_b_2", label="fork_b_3"),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_a_4"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_b_3", label="fork_b_4"),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_a_4"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="fork_b_4", label="fork_b_5"),
                checks=StoreChecks(head_slot=Slot(5), head_root_label="fork_b_5"),
            ),
        ],
    )
