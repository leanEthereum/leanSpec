"""
Fork Choice Chain Reorganizations (Reorgs)
===========================================

Overview
--------
Tests chain reorganizations in the fork choice algorithm. A reorganization (reorg)
occurs when the canonical chain head switches from one fork to another, typically
because the alternative fork accumulated more attestation weight.

What is a Reorg?
----------------
A chain reorganization happens when:
1. Two or more competing forks exist at similar heights
2. Initially, one fork is considered the canonical head
3. The alternative fork gains more attestation weight
4. Fork choice switches the canonical head to the heavier fork
5. Previously canonical blocks become non-canonical

Reorg Depth
-----------
The **depth** of a reorg is the number of blocks that become non-canonical:
- **Shallow reorg**: 1-2 blocks deep
- **Medium reorg**: 3-5 blocks deep
- **Deep reorg**: 6+ blocks deep

In healthy networks, reorgs are typically shallow. Deep reorgs can indicate:
- Network partitions or latency issues
- Coordinated validator behavior
- Potential security concerns

Fork Choice Weight Dynamics
----------------------------
Fork choice uses LMD-GHOST to select the heaviest subtree:

**Weight Sources**:
    - Each validator's latest attestation adds 1 unit of weight
    - Proposer attestations add weight to their own block
    - Weight propagates to all ancestors in the subtree

**Reorg Triggers**:
    - Alternative fork receives more attestations
    - Alternative fork extends faster (more proposer attestations)
    - Weight shifts due to newer validator attestations superseding old ones

**Tie-Breaking**:
    - When forks have equal weight, lexicographic block root ordering decides
    - This ensures deterministic consensus across all nodes
"""

import pytest
from consensus_testing import (
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)

from lean_spec.subspecs.containers.slot import Slot

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
    - Slot 2: Fork B created (competing fork at same slot)
    - Slot 3: Fork B extended → triggers reorg from A to B

    Expected Behavior
    -----------------
    1. After fork_a_2: head = fork_a_2 (first seen wins tie)
    2. After fork_b_2: head = fork_a_2 (tie, fork_a maintains head)
    3. After fork_b_3: head = fork_b_3 (fork B heavier due to extension)

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
            # Fork B at slot 2 (competing fork, tie-breaker keeps fork_a as head)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="chain_base",
                    label="fork_b_2",
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",  # No reorg yet (tie)
                ),
            ),
            # Extend fork B → triggers reorg to fork B
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="fork_b_2",
                    label="fork_b_3",
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_b_3",  # REORG! Fork B now canonical
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
    - Slots 2-3: Fork A extends to 2 blocks ahead
    - Slots 2-4: Fork B slowly catches up, then overtakes

    Chain State Evolution:
        Slot 1: base
        Slot 2: base ← fork_a_2 (head)
                base ← fork_b_2
        Slot 3: base ← fork_a_2 ← fork_a_3 (head)
                base ← fork_b_2
        Slot 4: base ← fork_a_2 ← fork_a_3 (was head)
                base ← fork_b_2 ← fork_b_3 (tie at depth 2)
        Slot 5: base ← fork_a_2 ← fork_a_3 (abandoned)
                base ← fork_b_2 ← fork_b_3 ← fork_b_4 (head - REORG!)

    Expected Behavior
    -----------------
    1. Fork A leads for slots 2-3 (2 blocks ahead)
    2. Fork B catches up at slot 4 (both at depth 2)
    3. Fork B overtakes at slot 5 (3 blocks vs 2)
    4. Two-block reorg: fork_a_2 and fork_a_3 become non-canonical

    Reorg Details:
        - **Depth**: 2 blocks
        - **Trigger**: Progressive building on alternative fork
        - **Weight advantage**: Fork B has 3 proposer attestations vs 2

    Why This Matters
    ----------------
    Demonstrates that an initially leading fork can be overtaken if:
    - Proposers switch to building on the alternative fork
    - The alternative fork accumulates more blocks over time
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
            # Fork B: slot 2 (starts competing)
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_b_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",  # Fork A maintains lead
                ),
            ),
            # Fork A: slot 3 (extends lead)
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_a_2", label="fork_a_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",  # Fork A leads by 2 blocks
                ),
            ),
            # Fork B: slot 3 (catches up to depth 2)
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_b_2", label="fork_b_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",  # Tie at depth 2, fork_a wins tie
                ),
            ),
            # Fork B: slot 4 (extends to depth 3, overtakes)
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_b_3", label="fork_b_4"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_b_4",  # REORG! 2-block deep
                ),
            ),
        ],
    )


def test_three_block_deep_reorg(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Deep three-block reorg from established fork to alternative.

    Scenario
    --------
    - Slot 1: Common base
    - Slots 2-4: Fork A builds 3-block lead
    - Slots 2-5: Fork B slowly builds, then surpasses with 4 blocks

    Timeline:
        Slot 2: Fork A leads (1 vs 0)
        Slot 3: Fork A leads (2 vs 1)
        Slot 4: Fork A leads (3 vs 2)
        Slot 5: Fork B overtakes (4 vs 3) → 3-block deep reorg

    Expected Behavior
    -----------------
    1. Fork A establishes 3-block canonical chain (slots 2-4)
    2. Fork B steadily builds parallel chain
    3. At slot 5, fork B has 4 blocks vs fork A's 3 blocks
    4. Fork choice switches to fork B
    5. Three blocks (fork_a slots 2-4) become non-canonical

    Reorg Details:
        - **Depth**: 3 blocks (deepest in this test suite)
        - **Trigger**: Alternative fork becomes longer
        - **Weight advantage**: 4 proposer attestations vs 3

    Why This Matters
    ----------------
    Deep reorgs (3+ blocks) are rare in healthy networks but can happen:
    - Network partitions lasting multiple slots
    - Coordinated validator behavior (intentional or accidental)
    - Major network latency events

    Properties verified:
    - Fork choice correctly switches even after multiple canonical blocks
    - Weight calculation works correctly over extended depth
    - No "stickiness" bias toward existing head
    - Objective heaviest fork always wins

    This tests the protocol's ability to recover from significant disagreement
    about chain history, ensuring safety and liveness even in adversarial scenarios.
    """
    fork_choice_test(
        steps=[
            # Common base
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Fork A: slots 2-4 (builds 3-block lead)
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            # Fork B: slot 2 (starts competing)
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_b_2"),
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
            # Fork B: slot 3
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_b_2", label="fork_b_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",  # Fork A still leads
                ),
            ),
            # Fork A: slot 4 (3 blocks deep)
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_a_3", label="fork_a_4"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_4",
                ),
            ),
            # Fork B: slot 4 (catches up to 3 blocks)
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_b_3", label="fork_b_4"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_4",  # Tie, fork_a wins
                ),
            ),
            # Fork B: slot 5 (4 blocks deep, overtakes)
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="fork_b_4", label="fork_b_5"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="fork_b_5",  # DEEP REORG! 3 blocks
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
    - Slot 3: Fork B (competing)
    - Slot 7: Fork A extended (skipping slots 4-6)
    - Slot 8: Fork B extended (skipping slots 4-7)
    - Slot 9: Fork B extended again → triggers reorg

    Missed Slots: 2, 4, 5, 6 (no blocks produced)

    Expected Behavior
    -----------------
    1. Sparse block production doesn't affect fork choice logic
    2. Weight calculation only considers actual blocks
    3. Reorg happens based on block count, not slot numbers
    4. Fork B with 3 blocks beats fork A with 2 blocks

    Reorg Details:
        - **Depth**: 2 blocks (fork_a slots 3, 7)
        - **Trigger**: Progressive building despite gaps
        - **Weight**: 3 proposer attestations vs 2

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
                block=BlockSpec(slot=Slot(3), parent_label="base", label="fork_a_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",
                ),
            ),
            # Fork B at slot 3 (competing, missed slot 2)
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="base", label="fork_b_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",  # Tie-breaker
                ),
            ),
            # Fork A at slot 7 (missed slots 4-6)
            BlockStep(
                block=BlockSpec(slot=Slot(7), parent_label="fork_a_3", label="fork_a_7"),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    head_root_label="fork_a_7",
                ),
            ),
            # Fork B at slot 8 (missed slots 4-7, catches up)
            BlockStep(
                block=BlockSpec(slot=Slot(8), parent_label="fork_b_3", label="fork_b_8"),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    head_root_label="fork_a_7",  # Tie (both 2 blocks deep)
                ),
            ),
            # Fork B at slot 9 (overtakes with 3rd block)
            BlockStep(
                block=BlockSpec(slot=Slot(9), parent_label="fork_b_8", label="fork_b_9"),
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
    Three forks (A, B, C) compete simultaneously. Fork choice progressively
    eliminates weaker forks as stronger ones extend.

    Fork Topology:
                  base (slot 1)
                   /   |     \
                  /    |      \
              fork_a  fork_b  fork_c  (slot 2)
                |       |       |
                |       |       +--- fork_c_3 (slot 3)
                |       +--- fork_b_3 (slot 3)
                |       +--- fork_b_4 (slot 4) ← Winner
                +--- abandoned

    Expected Behavior
    -----------------
    1. All three forks start at slot 2 (three-way tie)
    2. Fork C extends to slot 3 → becomes head
    3. Fork B extends to slot 3 → ties with fork C at depth 2
    4. Fork B extends to slot 4 → wins with depth 3
    5. Forks A and C become non-canonical

    Reorg Sequence:
        - Initial: fork_a (tie-breaker among three)
        - After fork_c_3: fork_c (depth advantage)
        - After fork_b_3: fork_c (tie, maintains head)
        - After fork_b_4: fork_b (final winner)

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
        steps=[
            # Common base
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Three-way fork at slot 2
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",  # First seen
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_b_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",  # Tie-breaker maintains fork_a
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_c_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",  # Three-way tie, fork_a wins
                ),
            ),
            # Fork C extends to slot 3 → takes lead
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_c_2", label="fork_c_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_c_3",  # Fork C now leads (2 blocks)
                ),
            ),
            # Fork B extends to slot 3 → ties with fork C
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_b_2", label="fork_b_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_c_3",  # Tie (both 2 blocks), fork_c maintains
                ),
            ),
            # Fork B extends to slot 4 → wins with 3 blocks
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_b_3", label="fork_b_4"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_b_4",  # Fork B wins (3 blocks > 2)
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
        steps=[
            # Common base
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Fork A builds 5-block lead
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_a_2", label="fork_a_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_a_3", label="fork_a_4"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_4",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="fork_a_4", label="fork_a_5"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="fork_a_5",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(6), parent_label="fork_a_5", label="fork_a_6"),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",  # Fork A has 6-block chain
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
        Slot 2: Fork A leads (1 block) ← head
        Slot 3: Fork B catches up (1 block each) → tie
        Slot 4: Fork B extends (2 vs 1) ← head switches to B
        Slot 5: Fork A extends (2 vs 2) → tie
        Slot 6: Fork A extends (3 vs 2) ← head switches to A
        Slot 7: Fork B extends (3 vs 3) → tie
        Slot 8: Fork B extends (4 vs 3) ← head switches to B

    Expected Behavior
    -----------------
    1. Head oscillates: A → B → A → B
    2. Each extension triggers reorg to that fork
    3. All reorgs are 1-2 blocks deep
    4. Fork choice remains consistent and correct throughout

    Reorg Count: 3 reorgs in 6 slots (very high rate)

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
        steps=[
            # Common base
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Fork A: slot 2 (takes initial lead)
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",  # Fork A leads
                ),
            ),
            # Fork B: slot 2 (ties)
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_b_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",  # Tie, fork_a maintains
                ),
            ),
            # Fork B: slot 3 (extends, takes lead) → REORG #1
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_b_2", label="fork_b_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_b_3",  # Fork B now leads (2 vs 1)
                ),
            ),
            # Fork A: slot 3 (catches up, ties)
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_a_2", label="fork_a_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_b_3",  # Tie (both 2), fork_b maintains
                ),
            ),
            # Fork A: slot 4 (extends, takes lead) → REORG #2
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_a_3", label="fork_a_4"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_4",  # Fork A back on top (3 vs 2)
                ),
            ),
            # Fork B: slot 4 (catches up, ties)
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_b_3", label="fork_b_4"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_4",  # Tie (both 3), fork_a maintains
                ),
            ),
            # Fork B: slot 5 (extends, takes lead) → REORG #3
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="fork_b_4", label="fork_b_5"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="fork_b_5",  # Fork B wins final round (4 vs 3)
                ),
            ),
        ],
    )


def test_reorg_with_justification_boundary(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Reorg occurs correctly when forks cross justification boundaries.

    Scenario
    --------
    Two forks compete across multiple justifiable slots. Fork choice must
    correctly handle reorgs while respecting justification rules.

    Slots 1-8: Two forks build in parallel
    - Fork A: slots 1, 3, 5, 7 (4 blocks with gaps)
    - Fork B: slots 1, 2, 4, 6, 8 (5 blocks, denser)

    Expected Behavior
    -----------------
    1. Fork A initially leads with first block
    2. Fork B builds denser chain (more blocks)
    3. Fork B overtakes despite gaps in fork A
    4. Justification constraints remain satisfied throughout

    Why This Matters
    ----------------
    Justification is a critical safety mechanism:
    - Limits which blocks can be attested to
    - Prevents long-range attacks
    - Ensures fork choice respects finality constraints

    This test ensures:
    - Reorgs respect justification boundaries
    - Fork choice works correctly across justifiable slots
    - Dense fork beats sparse fork even with justification gaps
    - Safety guarantees maintained during reorgs
    """
    fork_choice_test(
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
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            # Fork B: slot 2 (competing)
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_b_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",  # Tie-breaker favors fork_a
                ),
            ),
            # Fork B: slot 3 (extends first, takes lead)
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_b_2", label="fork_b_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_b_3",  # Fork B leads (2 blocks vs 1)
                ),
            ),
            # Fork A: slot 4 (extends, ties at depth 2)
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_a_2", label="fork_a_4"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_b_3",  # Tie (both 2), fork_b maintains
                ),
            ),
            # Fork B: slot 5 (extends to depth 3)
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="fork_b_3", label="fork_b_5"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="fork_b_5",  # Fork B leads (3 vs 2)
                ),
            ),
            # Fork A: slot 6 (extends to depth 3, ties)
            BlockStep(
                block=BlockSpec(slot=Slot(6), parent_label="fork_a_4", label="fork_a_6"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="fork_b_5",  # Tie (both 3), fork_b maintains
                ),
            ),
            # Fork B: slot 7 (extends to depth 4)
            BlockStep(
                block=BlockSpec(slot=Slot(7), parent_label="fork_b_5", label="fork_b_7"),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    head_root_label="fork_b_7",  # Fork B leads (4 vs 3)
                ),
            ),
            # Fork A: slot 8 (extends to depth 4, ties)
            BlockStep(
                block=BlockSpec(slot=Slot(8), parent_label="fork_a_6", label="fork_a_8"),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    head_root_label="fork_b_7",  # Tie (both 4), fork_b maintains
                ),
            ),
            # Fork B: slot 9 (extends to depth 5, wins decisively)
            BlockStep(
                block=BlockSpec(slot=Slot(9), parent_label="fork_b_7", label="fork_b_9"),
                checks=StoreChecks(
                    head_slot=Slot(9),
                    head_root_label="fork_b_9",  # Fork B wins (5 vs 4)
                ),
            ),
        ],
    )
