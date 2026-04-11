"""Fork Choice Head Selection (LMD-GHOST Algorithm)"""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex

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
    Fork choice selects head when two forks compete with equal weight.

    Scenario
    --------
    Create two competing forks from a common ancestor, each with one block
    at a distinct slot.

    Expected Behavior:
        - After slot 1: head = slot 1 (common ancestor)
        - After fork A (slot 2): head = fork A (only fork)
        - After fork B (slot 3): both forks have equal weight
          (1 proposer attestation each), head chosen by lexicographic tiebreaker

    Why This Matters
    ----------------
    This is an important fork choice scenario: two forks of equal weight
    competing for the head. Fork choice must deterministically select a head.

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
            # Fork B at slot 3 (same parent as fork A, equal weight)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="common",
                    label="fork_b",
                ),
                # Both forks have equal weight (1 proposer attestation each)
                # Head determined by lexicographic tiebreaker on block roots
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a", "fork_b"],
                ),
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
    Create two forks from a common ancestor at distinct slots, then extend
    one fork to make it heavier.

    Expected Behavior:
        - After fork A (slot 2): head = fork A (only fork)
        - After fork B (slot 3): equal weight, tiebreaker decides
        - After extending fork B (slot 4): head = fork B's child (fork B wins!)

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
            # Fork B at slot 3 (same parent, equal weight, tiebreaker decides)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="common",
                    label="fork_b",
                ),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a", "fork_b"],
                ),
            ),
            # Extend fork B with an attestation for fork_b → gives it more weight
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_b",
                    label="fork_b_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(2)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_b",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_b_4"),
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
    Create two forks that diverge from a common ancestor but are built
    at different slots (no duplicate slots).

    Expected Behavior:
        - Fork A extends earlier to slot 4
        - Fork B starts later but extends to slot 8
        - Head eventually follows the heavier fork B

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
            # Fork A: earlier branch (slots 2 - 4)
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="common", label="fork_a_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a_2"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="fork_a_2",
                    label="fork_a_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(2)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="fork_a_2",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="fork_a_3"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_a_3",
                    label="fork_a_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(3)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_a_3",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_a_4"),
            ),
            # Fork B: competing branch starting later (slots 5 - 8)
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="common", label="fork_b_5"),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_a_4"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_b_5",
                    label="fork_b_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(1)],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_b_5",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_a_4"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(7),
                    parent_label="fork_b_6",
                    label="fork_b_7",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0)],
                            slot=Slot(6),
                            target_slot=Slot(6),
                            target_root_label="fork_b_6",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
                    parent_label="fork_b_7",
                    label="fork_b_8",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(2)],
                            slot=Slot(7),
                            target_slot=Slot(7),
                            target_root_label="fork_b_7",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(8), head_root_label="fork_b_8"),
            ),
        ],
    )


def test_head_selection_by_weight_not_depth(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Shorter fork with more attestation weight wins over deeper fork.

    Scenario
    --------
    Six validators. Two forks diverge from a common ancestor::

        genesis -> common(1)
            |- a_2 -> a_3 -> a_4 -> a_5 -> a_6   (5 deep, V0 attests)
            +- b_9 -> b_12                         (2 deep, V1-V3 attest)

    - Fork A: 5 blocks, 1 attestation (V0 on a_2)
    - Fork B: 2 blocks, 3 attestations (V1-V3 on b_9)
    - 3 attesters stay below the 2/3 threshold (3*3=9 < 2*6=12),
      so no justification is triggered

    Expected post-state
    -------------------
    - Head = b_12 (weight 3 > weight 1 at the fork point)
    - Justified slot: 0 (unchanged, no supermajority reached)
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            # Fork point for both chains.
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            # Fork A: 5 blocks deep, minimal attestation weight
            # ===================================================
            #
            #   common(1) -> a_2 -> a_3 -> a_4 -> a_5 -> a_6
            #
            # Only V0 attests (in a_3, targeting a_2).
            # Five blocks but just 1 unit of attestation weight.
            BlockStep(block=BlockSpec(slot=Slot(2), parent_label="common", label="a_2")),
            # V0 attests to a_2. This is fork A's only attestation weight.
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="a_2",
                    label="a_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="a_2",
                        ),
                    ],
                ),
            ),
            BlockStep(block=BlockSpec(slot=Slot(4), parent_label="a_3", label="a_4")),
            BlockStep(block=BlockSpec(slot=Slot(5), parent_label="a_4", label="a_5")),
            # After a_6: fork A is the only branch, so it is the head.
            BlockStep(
                block=BlockSpec(slot=Slot(6), parent_label="a_5", label="a_6"),
                checks=StoreChecks(head_slot=Slot(6), head_root_label="a_6"),
            ),
            # Fork B: 2 blocks deep, heavy attestation weight
            # =================================================
            #
            #   common(1) -> b_9 -> b_12
            #
            # Slot 9 is justifiable after finalized=0: delta=9, perfect
            # square (3^2). Slot 12: delta=12, pronic (3*4).
            #
            # Three validators (V1-V3) attest in b_12, targeting b_9.
            # Threshold: 3*3=9 < 2*6=12 -> below 2/3 supermajority,
            # so NO justification is triggered. This ensures the test
            # exercises pure weight comparison, not justification pruning.
            # After b_9: no attestations yet, fork A still heavier -> head stays on a_6.
            BlockStep(
                block=BlockSpec(slot=Slot(9), parent_label="common", label="b_9"),
                checks=StoreChecks(head_slot=Slot(6), head_root_label="a_6"),
            ),
            # b_12 carries 3 attestations for b_9.
            # At the fork point "common", the weight comparison is:
            #   Fork A subtree: 1 (V0)
            #   Fork B subtree: 3 (V1, V2, V3)
            # LMD-GHOST descends into fork B -> head = b_12.
            BlockStep(
                block=BlockSpec(
                    slot=Slot(12),
                    parent_label="b_9",
                    label="b_12",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                                ValidatorIndex(3),
                            ],
                            slot=Slot(9),
                            target_slot=Slot(9),
                            target_root_label="b_9",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(12),
                    head_root_label="b_12",
                    # Invariant: no justification triggered (3 < 4 needed for 2/3).
                    latest_justified_slot=Slot(0),
                ),
            ),
        ],
    )
