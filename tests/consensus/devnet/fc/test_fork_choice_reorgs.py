"""Fork Choice Chain Reorganizations (Reorgs)"""

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


def test_simple_one_block_reorg(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Simplest reorg: one-block fork overtakes another via extension.

    Scenario
    --------
    - Slot 1: Common ancestor (chain_base)
    - Slot 2: Fork A created, becomes head
    - Slot 3: Fork B created (competing fork from same parent)
    - Slot 4: Fork B extended → triggers reorg from A to B

    Expected Behavior
    -----------------
    1. After fork_a_2: head = fork_a_2 (only fork)
    2. After fork_b_3: equal weight, tiebreaker decides
    3. After fork_b_4: head = fork_b_4 (fork B heavier due to extension)

    Reorg Details:
        - **Depth**: 1 block (fork_a_2 becomes non-canonical)
        - **Trigger**: Fork extension (proposer attestation)
        - **Weight advantage**: Fork B has 2 proposer attestations vs 1

    Why This Matters
    ----------------
    This is the most common reorg scenario in practice:
    - Two blocks proposed at nearly the same time
    - Network temporarily splits (half see A first, half see B first)
    - Next proposer builds on one fork, resolving the split
    - Fork choice converges to the extended fork

    Tests the fundamental property: extending a fork makes it heavier.
    """
    fork_choice_test(
        steps=[
            # Common ancestor at slot 1
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="chain_base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="chain_base",
                ),
            ),
            # Fork A at slot 2 (becomes initial head)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="chain_base",
                    label="fork_a_2",
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            # Fork B at slot 3 (same parent, equal weight)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="chain_base",
                    label="fork_b_3",
                ),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a_2", "fork_b_3"],
                ),
            ),
            # Extend fork B with attestation → triggers reorg to fork B
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_b_3",
                    label="fork_b_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(2)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_b_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_b_4",
                ),
            ),
        ],
    )


def test_two_block_reorg_progressive_building(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Two-block reorg via progressive fork building.

    Scenario
    --------
    - Slot 1: Common ancestor
    - Slots 2-3: Fork A extends to 2 blocks
    - Slots 4-6: Fork B starts late from base, catches up, then overtakes

    Chain State Evolution:
        Slot 1: base
        Slot 2: base ← fork_a_2 (head)
        Slot 3: base ← fork_a_2 ← fork_a_3 (head, weight=1)
        Slot 4: base ← fork_a_2 ← fork_a_3 (head, weight=1)
                base ← fork_b_4
        Slot 5: base ← fork_a_2 ← fork_a_3 (head, weight=1)
                base ← fork_b_4 ← fork_b_5
        Slot 6: base ← fork_a_2 ← fork_a_3 (weight=1, abandoned)
                base ← fork_b_4 ← fork_b_5 ← fork_b_6 (head, weight=2 - REORG!)

    Expected Behavior
    -----------------
    1. Fork A leads for slots 2-3 (2 blocks, weight=1)
    2. Fork B starts late at slot 4 (builds on base)
    3. Fork B overtakes at slot 6 (weight=2 > fork A's 1)
    4. Two-block reorg: fork_a_2 and fork_a_3 become non-canonical

    Reorg Details:
        - **Depth**: 2 blocks
        - **Trigger**: Progressive building on alternative fork
        - **Weight advantage**: Fork B has 2 attestations vs 1

    Why This Matters
    ----------------
    Demonstrates that an initially leading fork can be overtaken if:
    - Proposers switch to building on the alternative fork
    - The alternative fork accumulates more attestations over time
    - Network temporarily favored one fork but consensus shifted
    """
    fork_choice_test(
        steps=[
            # Common ancestor
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Fork A: slot 2
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            # Fork A: slot 3 (extends lead with attestation, weight=1)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="fork_a_2",
                    label="fork_a_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="fork_a_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",  # Fork A leads (weight=1)
                ),
            ),
            # Fork B: slot 4 (starts late from base, fork A still leads)
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="base", label="fork_b_4"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",  # Fork A leads (weight=1 vs 0)
                ),
            ),
            # Fork B: slot 5
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="fork_b_4", label="fork_b_5"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",  # Fork A still leads (weight=1 vs 0)
                ),
            ),
            # Fork B: slot 6 (2 attestations overtake fork A's 1)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_b_5",
                    label="fork_b_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(1), ValidatorIndex(3)],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_b_5",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_b_6",  # REORG! 2-block deep
                ),
            ),
        ],
    )


def test_three_block_deep_reorg(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Three-block reorg where a shorter fork wins via attestation weight.

    Scenario
    --------
    - Slot 1: Common base
    - Slots 2-4: Fork A builds 3-block chain with 2 attestations (validators 2, 3)
    - Slot 5: Fork B branches from base with 0 weight, fork A still leads
    - Slot 6: Fork B gains 3 attestations (validators 0, 2, 5) → reorg

    Fork B is shorter (2 blocks) but heavier (3 attestations vs 1).
    Validator 2 switches from fork A to fork B, reducing fork A's net weight.

    Timeline:
        Slot 4: Fork A = 2 (validators 2, 3), fork B = 0
        Slot 5: Fork A = 2, fork B = 0 (fork B has 1 block, still lighter)
        Slot 6: Fork A = 1 (validator 3), fork B = 3 (validators 0, 2, 5) → reorg

    Properties verified:
    - Fork choice correctly switches even after multiple canonical blocks
    - Weight calculation works correctly over extended depth
    - No "stickiness" bias toward existing head
    - Objective heaviest fork always wins

    This tests the protocol's ability to recover from significant disagreement
    about chain history, ensuring safety and liveness even in adversarial scenarios.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            # Common base
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Fork A: slot 2
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            # Fork A: slot 3
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_a_2", label="fork_a_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",
                ),
            ),
            # Fork A: slot 4 (with attestations for fork_a_3, weight=2)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_a_3",
                    label="fork_a_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(2), ValidatorIndex(3)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_a_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_4",
                ),
            ),
            # Fork B: slot 5 (branches from base, fork A still leads)
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="base", label="fork_b_5"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_4",  # Fork A leads (weight=2 vs 0)
                ),
            ),
            # Fork B: slot 6 (3 attestations overtake fork A's weight)
            # Validator 2 switches allegiance: was attesting to fork A, now fork B.
            # Net weight: fork A = 1 (validator 3), fork B = 3 (validators 0, 2, 5)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_b_5",
                    label="fork_b_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(0),
                                ValidatorIndex(2),
                                ValidatorIndex(5),
                            ],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_b_5",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_b_6",  # DEEP REORG! 3 blocks
                ),
            ),
        ],
    )


def test_reorg_with_slot_gaps(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Reorg occurs correctly even with missed slots in the chain.

    Scenario
    --------
    - Slot 1: Base
    - Slot 3: Fork A (skipping slot 2)
    - Slot 4: Fork B (competing)
    - Slot 7: Fork A extended (skipping slots 4-6)
    - Slot 8: Fork B extended with explicit attestations (skipping slots 5-7)
    - Slot 9: Fork B extended again → triggers reorg

    Missed Slots: 2, 5, 6 (no blocks produced)

    Expected Behavior
    -----------------
    1. Sparse block production doesn't affect fork choice logic
    2. Weight calculation only considers actual blocks
    3. Reorg happens based on attestation weight, not slot numbers

    Weight Dynamics
    ---------------
    Fork A accumulates 3 organic proposer gossip votes:

    - V3 (fork_a_3 proposer): votes for Fork A
    - V4 (fork_b_4 proposer): votes for Fork A (head points to A when V4 attests)
    - V7 (fork_a_7 proposer): votes for Fork A

    Fork B overcomes with 4 explicit attestations in fork_b_8's body
    from non-proposer validators {0, 2, 5, 6}, then reinforced by
    fork_b_8 and fork_b_9 proposer gossip.

    Why This Matters
    ----------------
    Missed slots are extremely common in production:
    - Offline validators (expected ~1% downtime)
    - Network issues preventing timely block propagation
    - Intentional skips during network congestion

    Fork choice must remain robust with sparse block production:
    - Gaps don't create bias toward any fork
    - Only actual blocks contribute weight
    - Reorg logic works identically whether slots are consecutive or sparse

    This test ensures the algorithm works correctly in realistic network
    conditions where perfect block production is impossible.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=10),
        steps=[
            # Base at slot 1
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Fork A at slot 3 (missed slot 2)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="base",
                    label="fork_a_3",
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",
                ),
            ),
            # Fork B at slot 4 (competing, missed slot 2-3)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="base",
                    label="fork_b_4",
                ),
            ),
            # Fork A at slot 7 (missed slots 4-6) with attestation for fork A
            BlockStep(
                block=BlockSpec(
                    slot=Slot(7),
                    parent_label="fork_a_3",
                    label="fork_a_7",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(3)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_a_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    head_root_label="fork_a_7",
                ),
            ),
            # Fork B at slot 8 with explicit attestations for fork_b's chain.
            #
            # Four non-proposer validators explicitly attest to fork_b_4,
            # giving Fork B 4 votes vs Fork A's 1.
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
                    parent_label="fork_b_4",
                    label="fork_b_8",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(0),
                                ValidatorIndex(2),
                                ValidatorIndex(5),
                                ValidatorIndex(6),
                            ],
                            slot=Slot(4),
                            target_slot=Slot(4),
                            target_root_label="fork_b_4",
                        ),
                    ],
                ),
            ),
            # Fork B at slot 9
            BlockStep(
                block=BlockSpec(
                    slot=Slot(9),
                    parent_label="fork_b_8",
                    label="fork_b_9",
                ),
                # Fork B overtakes Fork A. REORG.
                #
                # Fork A: 1 vote (V3 explicit)
                # Fork B: 4 votes (V0, V2, V5, V6 explicit)
                checks=StoreChecks(
                    head_slot=Slot(9),
                    head_root_label="fork_b_9",  # REORG with sparse blocks
                ),
            ),
        ],
    )


def test_three_way_fork_competition(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Three competing forks with progressive elimination until one wins.

    Scenario
    --------
    Three forks (A, B, C) compete from a common ancestor, each at a distinct
    slot. Fork choice progressively eliminates weaker forks as stronger ones
    extend.

    Fork Topology:
                       base (slot 1)
                      /    |       \
                     /     |        \
              fork_a_2  fork_b_3  fork_c_4
              (slot 2)  (slot 3)  (slot 4)
                |          |         |
                |          |         +--- fork_c_5 (slot 5)
                |          +--- fork_b_6 (slot 6)
                |          +--- fork_b_7 (slot 7) ← Winner
                +--- abandoned

    Expected Behavior
    -----------------
    1. Three forks created at slots 2, 3, 4 (equal weight, three-way tie)
    2. Fork C extends to slot 5 with attestation → becomes head
    3. Fork B extends to slot 6 (no attestation) → fork C still leads
    4. Fork B extends to slot 7 with 2 attestations → wins
    5. Forks A and C become non-canonical

    Why This Matters
    ----------------
    Multi-fork scenarios can occur during:
    - Network partitions splitting validators 3+ ways
    - Rapid block production creating multiple conflicting proposals
    - Byzantine validators intentionally creating competing forks

    Properties verified:
    - Fork choice handles 3+ simultaneous competing forks
    - Head selection remains consistent and deterministic
    - Progressive elimination works correctly
    - Final winner is objectively the heaviest fork
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            # Common base
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Three forks at distinct slots (2, 3, 4)
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="base",
                    label="fork_b_3",
                ),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a_2", "fork_b_3"],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="base",
                    label="fork_c_4",
                ),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a_2", "fork_b_3", "fork_c_4"],
                ),
            ),
            # Fork C extends to slot 5 with attestation → takes lead
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    parent_label="fork_c_4",
                    label="fork_c_5",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0)],
                            slot=Slot(4),
                            target_slot=Slot(4),
                            target_root_label="fork_c_4",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="fork_c_5",
                ),
            ),
            # Fork B extends to slot 6 (no attestation, fork C still leads)
            BlockStep(
                block=BlockSpec(slot=Slot(6), parent_label="fork_b_3", label="fork_b_6"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="fork_c_5",
                ),
            ),
            # Fork B extends to slot 7 with 2 attestations → wins
            BlockStep(
                block=BlockSpec(
                    slot=Slot(7),
                    parent_label="fork_b_6",
                    label="fork_b_7",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(1), ValidatorIndex(2)],
                            slot=Slot(6),
                            target_slot=Slot(6),
                            target_root_label="fork_b_6",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    head_root_label="fork_b_7",
                ),
            ),
        ],
    )


def test_reorg_prevention_heavy_fork_resists_light_competition(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Established heavy fork successfully resists light competing fork.

    Scenario
    --------
    - Fork A builds substantial lead (5 blocks)
    - Fork B created late, builds 3 blocks
    - Fork A maintains head despite fork B's growth

    Chain Evolution:
        Slots 1-5: Fork A builds uncontested (5 blocks)
        Slot 6:    Fork B starts from slot 1 (late competitor)
        Slots 6-8: Fork B builds 3 blocks (total 3 vs fork A's 5)
        Result:    Fork A remains canonical (reorg prevented)

    Expected Behavior
    -----------------
    1. Fork A establishes 5-block lead
    2. Fork B starts competing from an earlier slot
    3. Fork B builds rapidly but can't match fork A's depth
    4. Head remains on fork A throughout (no reorg)

    Why This Matters
    ----------------
    Reorg resistance is crucial for chain stability:
    - Prevents cheap disruption of established chain
    - Requires substantial work to overtake canonical fork
    - Protects against late-arriving competing forks
    - Ensures finality can eventually be reached

    Attack Prevention:
    - Attacker can't easily reorg established blocks
    - Must match or exceed weight of canonical chain
    - Time advantage gives canonical chain strong position
    - Network naturally converges on heaviest fork
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=12),
        steps=[
            # Common base
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Fork A builds 5-block lead with attestations for weight.
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="base",
                    label="fork_a_2",
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
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
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",
                ),
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
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_4",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    parent_label="fork_a_4",
                    label="fork_a_5",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(4)],
                            slot=Slot(4),
                            target_slot=Slot(4),
                            target_root_label="fork_a_4",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="fork_a_5",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_a_5",
                    label="fork_a_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(5)],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_a_5",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",  # Fork A has weight=4
                ),
            ),
            # Fork B attempts to compete (starting from base, building late)
            BlockStep(
                block=BlockSpec(slot=Slot(7), parent_label="base", label="fork_b_2"),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",  # Fork A maintains head (6 vs 1)
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(8), parent_label="fork_b_2", label="fork_b_3"),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",  # Fork A still leads (6 vs 2)
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(9), parent_label="fork_b_3", label="fork_b_4"),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",  # Fork A resists (6 vs 3) - No reorg!
                ),
            ),
        ],
    )


def test_back_and_forth_reorg_oscillation(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Multiple reorgs as two forks alternately extend (pathological case).

    Scenario
    --------
    Two forks alternate extensions, causing head to oscillate back and forth.
    This is a pathological case that shouldn't happen in healthy networks but
    tests fork choice correctness under extreme conditions.

    Oscillation Pattern:
        Slot 2: Fork A created ← head (only fork)
        Slot 3: Fork B created → tie, tiebreaker decides
        Slot 4: Fork B extends with attestation ← head switches to B (REORG #1)
        Slot 5: Fork A extends (no attestation) → B still leads
        Slot 6: Fork A extends with 2 attestations ← head switches to A (REORG #2)
        Slot 7: Fork B extends (no attestation) → A still leads
        Slot 8: Fork B extends with 2 attestations ← head switches to B (REORG #3)

    Expected Behavior
    -----------------
    1. Head oscillates: A → B → A → B
    2. Each extension with attestations triggers reorg to that fork
    3. Fork choice remains consistent and correct throughout

    Why This Matters
    ----------------
    While extremely rare, this scenario can theoretically occur:
    - Two validator groups in different network segments
    - Each group primarily seeing their own fork first
    - Alternating proposer selection between groups
    - High network latency preventing convergence

    Properties Tested:
    - Fork choice handles rapid reorg sequences
    - No state corruption despite frequent head changes
    - Tie-breaking remains consistent
    - Weight calculation correct after multiple reorgs
    - System eventually stabilizes to heaviest fork

    This stress test verifies robustness under worst-case fork competition,
    ensuring the protocol remains safe even in pathological network conditions.
    In practice, networks self-heal from such scenarios through attestation
    convergence.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=10),
        steps=[
            # Common base
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Fork A at slot 2 (takes initial lead)
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            # Fork B at slot 3 (ties, tiebreaker decides)
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="base", label="fork_b_3"),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a_2", "fork_b_3"],
                ),
            ),
            # Fork B extends to slot 4 with attestation → REORG #1
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_b_3",
                    label="fork_b_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_b_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_b_4",
                ),
            ),
            # Fork A extends to slot 5 (catches up, no attestation)
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="fork_a_2", label="fork_a_5"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_b_4",
                ),
            ),
            # Fork A extends to slot 6 with 2 attestations → REORG #2
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_a_5",
                    label="fork_a_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(9), ValidatorIndex(8)],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_a_5",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",
                ),
            ),
            # Fork B extends to slot 7 (catches up, no attestation)
            BlockStep(
                block=BlockSpec(slot=Slot(7), parent_label="fork_b_4", label="fork_b_7"),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",
                ),
            ),
            # Fork B extends to slot 8 with 2 attestations → REORG #3
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
                    parent_label="fork_b_7",
                    label="fork_b_8",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(1), ValidatorIndex(9)],
                            slot=Slot(7),
                            target_slot=Slot(7),
                            target_root_label="fork_b_7",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(8),
                    head_root_label="fork_b_8",
                ),
            ),
        ],
    )


def test_reorg_on_newly_justified_slot(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Reorg occurs correctly when forks cross justification boundaries.

    Scenario
    --------
    Two forks compete. Fork A is heavier and longer, but Fork B manages to
    become justified. Fork choice must switch to the justified fork regardless
    of weight/length.

    - Slot 1: Base
    - Slots 2-4: Fork A extends (becomes head with depth 3)
    - Slot 5: Fork B appears (descending from Base, skipping slots 2-4)
    - Slot 6: Fork B extends. This block contains enough attestations to
              justify Fork B at Slot 5.

    Expected Behavior
    -----------------
    1. Fork A takes the lead initially (Slots 2-4) as the heaviest chain.
    2. Fork B appears at Slot 5 but is initially lighter.
    3. At Slot 6, the new block includes attestations that justify Fork B at Slot 5.
    4. The justified checkpoint updates to Slot 5 (fork_b_1).
    5. Fork A is immediately discarded because it does not descend from the new
       justified checkpoint (Fork A is on a branch from Slot 1).
    6. Fork B becomes the canonical head.

    Why This Matters
    ----------------
    Justification is a critical safety mechanism:
    - Limits which blocks can be attested to
    - Ensures fork choice respects finality constraints

    This test ensures:
    - Reorgs respect justification boundaries
    - Fork choice works correctly across justifiable slots
    - Safety guarantees maintained during reorgs
    """
    fork_choice_test(
        # Using 9 validators: 3 for Fork A and 6 for Fork B to achieve 2/3rd for Fork B
        anchor_state=generate_pre_state(num_validators=9),
        steps=[
            # Common base at slot 1
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Fork A: slot 2
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="base",
                    label="fork_a_1",
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_1",
                ),
            ),
            # Fork A: slot 3 with attestation targeting fork_a_1
            #
            # V2's head vote points to fork_a_1, which is in fork A's subtree.
            # This gives fork A weight=1, ensuring it leads over fork B
            # until fork B achieves justification.
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="fork_a_1",
                    label="fork_a_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(2)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="fork_a_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_2",
                ),
            ),
            # Fork A: slot 4
            # Fork A is the heaviest chain (3 blocks from justified slot)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_a_2",
                    label="fork_a_3",
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_3",
                ),
            ),
            # Fork B: slot 5 (first block of fork B)
            # Fork A is still the heaviest chain (3 blocks from justified slot)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    parent_label="base",
                    label="fork_b_1",
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_3",
                ),
            ),
            # Fork B: slot 6
            # Validator 5 justified fork_b_1 in slot 5
            # Validator 6 justifying fork_b_2 in slot 6
            # Add extra justifications on fork_b_1 from validator 0, 1, 7, 8
            # This makes fork_b_1 justified by 2/3rd of validators: 0, 1, 5, 6, 7, 8
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_b_1",
                    label="fork_b_2",
                    attestations=[
                        # Aggregated attestation from validators 0, 1, 5, 6, 7, 8
                        # fork_b_1 should be able to justify without extra attestations
                        # from validator 5 and 6 but the test is failing without these
                        # because block proposer's attestations are not being counted
                        # towards justification
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(5),
                                ValidatorIndex(6),
                                ValidatorIndex(7),
                                ValidatorIndex(8),
                            ],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_b_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_b_2",  # Fork B now leads as fork_b_1 is justified
                    latest_justified_slot=Slot(5),
                    latest_justified_root_label="fork_b_1",
                ),
            ),
        ],
    )
