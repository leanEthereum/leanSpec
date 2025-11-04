"""
Attestation Target Selection and Safe Target Computation
========================================================

Overview
--------
Tests the attestation target selection algorithm.
The target determines which checkpoint validators should attest to,
balancing between head advancement and safety guarantees.

Validation Approach
-------------------
These tests validate **complete checkpoints** (both slot and root).

When specifying the attestation target slot, validation automatically checks:
1. The checkpoint slot matches the expected value
2. The checkpoint root references an actual block at that slot

Attestation Target Algorithm
----------------------------
The attestation target algorithm determines which checkpoint (root + slot) validators
should attest to. This algorithm:

1. **Starts at Head**: Begin with the current head block
2. **Walks Toward Safe**: Move backward toward the safe target
3. **Respects Finalization**: Must be justifiable after the finalized checkpoint
4. **Balances Safety**: Optimizes between rapid head advancement and safety

Key Concepts
------------

**Attestation Target**:
    - The checkpoint that validators should attest to in their next attestation.
    - Computed dynamically based on head, safe_target, and finalization status.

**Safe Target**:
    - A checkpoint with sufficient attestation support to be considered "safe".
    - Updated based on latest attestation weights and supermajority threshold.

**Justifiable Slot**:
    - A slot that can be justified after the finalized checkpoint.
    - The target must be justifiable relative to the finalized slot.
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


def test_attestation_target_at_genesis_initially(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation target starts at genesis before safe target updates.

    Scenario
    --------
    Process two blocks at slots 1 and 2.

    Expected:
        - After slot 1: target = slot 0 (genesis/finalized)
        - After slot 2: target = slot 0 (genesis/finalized)
        - Target root automatically validated against block at slot 0

    Why This Matters
    ----------------
    Initially, the safe target is at genesis (slot 0), so the attestation
    target walks back from head to genesis.

    This conservative behavior ensures validators don't attest too far ahead
    before there's sufficient attestation weight to advance the safe target.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_target_slot=Slot(0),  # Still genesis
                ),
            ),
        ],
    )


def test_attestation_target_advances_with_attestations(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation target advances as attestation weight accumulates.

    Scenario
    --------
    Build a longer chain (slots 1-5) where attestations cause target advancement.

    Expected:
        - Initial blocks: target stays at genesis (slot 0)
        - Later blocks: target advances as attestations accumulate
        - Target remains behind head for safety

    Why This Matters
    ----------------
    As validators attest to blocks, the safe target advances, which in turn
    allows the attestation target to move forward.

    This demonstrates the dynamic nature of target selection: conservative initially,
    but advancing as consensus strengthens through attestation accumulation.

    The target advances only when sufficient attestation weight supports it.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),  # Still at genesis
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_target_slot=Slot(0),  # Still at genesis
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_target_slot=Slot(0),  # Still at genesis
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4)),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    attestation_target_slot=Slot(1),  # Advances to slot 1
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_target_slot=Slot(2),  # Continues advancing
                ),
            ),
        ],
    )


def test_attestation_target_with_slot_gaps(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation target handles missed slots correctly.

    Scenario
    --------
    Process blocks at slots 1, 3, 5 (skipping even slots).

    Expected:
        - Targets advance despite gaps
        - Targets remain justifiable
        - Safe target stays valid

    Why This Matters
    ----------------
    Missed slots are common when proposers fail or network partitions occur.

    The target selection must handle sparse block production gracefully,
    ensuring validators can still make progress even with gaps in the chain.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_target_slot=Slot(0),
                ),
            ),
        ],
    )


def test_attestation_target_with_extended_chain(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation target advances progressively over extended chain.

    Scenario
    --------
    Build a longer chain (slots 1-8) observing target advancement pattern.

    Expected:
        - Initial slots: target at genesis (conservative)
        - Middle slots: target advances to slot 1
        - Target advances gradually, not jumping to head

    Why This Matters
    ----------------
    Over extended chains, the target selection should show smooth,
    gradual advancement as attestation weight accumulates.

    The target lags behind the head, providing a stable reference point that
    advances only when sufficient consensus has formed. This prevents validators
    from attesting too far ahead without adequate safety guarantees.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),  # Genesis
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_target_slot=Slot(0),  # Still genesis
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_target_slot=Slot(0),  # Still genesis
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4)),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    attestation_target_slot=Slot(1),  # Advances to slot 1
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_target_slot=Slot(2),  # Stable at 2
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(6)),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    attestation_target_slot=Slot(3),  # Continues to advance
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7)),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    attestation_target_slot=Slot(4),  # Continues advancing
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(8)),
                checks=StoreChecks(
                    head_slot=Slot(8),
                    attestation_target_slot=Slot(5),  # Continues advancing
                ),
            ),
        ],
    )


def test_attestation_target_justifiable_constraint(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation target advances while respecting justifiability rules.

    Scenario
    --------
    Build a 10-slot chain and observe how the attestation target advances
    over time while remaining justifiable relative to genesis (finalized at slot 0).

    Justifiability Rules (see Slot.is_justifiable_after)
    -----------------------------------------------------

    The target starts from current head and walks back at most 3 slots towards safe target.

    Then, a slot is deemed justifiable at distance delta from finalization if:
    1. delta ≤ 5
    2. delta is a perfect square (1, 4, 9, 16, 25, ...)
    3. delta is a pronic number (2, 6, 12, 20, 30, ...)

    Expected Target Advancement:
        - Slots 1-3: 3-slot walkback target = slot 0
          delta = slot 0 (target) - slot 0 (finalized) = 0
          Use Rule 1: delta 0 ≤ 5

        - Slot 4: 3-slot walkback target = slot 1
          delta = slot 1 (target) - slot 0 (finalized) = 1
          Uses Rule 1: delta 1 ≤ 5

        - Slot 5: 3-slot walkback target = slot 2
          delta = slot 2 (target) - slot 0 (finalized) = 2
          Uses Rule 1: delta 2 ≤ 5

        - Slot 6: 3-slot walkback target = slot 3
          delta = slot 3 (target) - slot 0 (finalized) = 3
          Uses Rule 1: delta 3 ≤ 5

        - Slot 7: 3-slot walkback target = slot 4
          delta = slot 4 (target) - slot 0 (finalized) = 4
          Uses Rule 1: delta 4 ≤ 5

        - Slot 8: 3-slot walkback target = slot 5
          delta = slot 5 (target) - slot 0 (finalized) = 5
          Uses Rule 1: delta 5 ≤ 5

        - Slot 9: 3-slot walkback target = slot 6
          delta = slot 6 (target) - slot 0 (finalized) = 6
          Uses Rule 3: delta 6 is pronic (2×3)

        - Slot 10: 3-slot walkback target = slot 7
          delta = slot 7 (target) - slot 0 (finalized) = 7
          Target can't advance: delta 7 fails all rules

        - Slot 11: 3-slot walkback target = slot 8
          delta = slot 8 (target) - slot 0 (finalized) = 8
          Target can't advance: delta 8 fails all rules

        - Slot 12: 3-slot walkback target = slot 9
          delta = slot 9 (target) - slot 0 (finalized) = 9
          Uses Rule 2: delta 9 is a perfect square (3^2)

        - Slot 13: 3-slot walkback target = slot 10
          delta = slot 10 (target) - slot 0 (finalized) = 10
          Target can't advance: delta 10 fails all rules

    Why This Matters
    ----------------
    The justifiability rules prevent long-range attacks by restricting which
    checkpoints validators can attest to. The mathematical pattern (perfect squares
    and pronic numbers) creates increasingly sparse justifiable slots as the chain
    grows beyond finalization, providing security guarantees.

    The test verifies that the target selection algorithm respects these rules
    and never selects a non-justifiable target.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(i)),
                checks=StoreChecks(
                    head_slot=Slot(i),
                    # Target advancement pattern:
                    # - Slot 1: target = 0 (3-slot walkback reaches safe target at slot 0)
                    # - Slot 2: target = 0 (3-slot walkback reaches safe target at slot 0)
                    # - Slot 3: target = 0 (3-slot walkback reaches safe target at slot 0)
                    # - Slot 4: target = 1 (begins advancing)
                    # - Slot 5: target = 2
                    # - Slot 6: target = 3
                    # - Slot 7: target = 4
                    # - Slot 8: target = 5
                    # - Slot 9: target = 6
                    # - Slot 10: target = 6 (advancement slows)
                    # - Slot 11: target = 6 (advancement slows)
                    # - Slot 12: target = 9
                    # - Slot 13: target = 9 (advancement slows)
                    attestation_target_slot=Slot(
                        0 if i <= 3 else (i - 3 if i <= 9 else (6 if i <= 11 else 9))
                    ),
                ),
            )
            for i in range(1, 13)
        ],
    )
