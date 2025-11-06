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
                    attestation_target_slot=Slot(
                        # Mapping of current slot -> expected target slot
                        # delta = current_slot - JUSTIFICATION_LOOKBACK_SLOTS - finalized_slot
                        # delta = current_slot - 3 - 0
                        {
                            1: 0,  # 3-slot walkback reaches safe target at slot 0
                            2: 0,  # 3-slot walkback reaches safe target at slot 0
                            3: 0,  # 3-slot walkback reaches safe target at slot 0
                            4: 1,  # delta = 4 - 3 - 0 = 1, Rule 1: delta 1 ≤ 5
                            5: 2,  # delta = 5 - 3 - 0 = 2, Rule 1: delta 2 ≤ 5
                            6: 3,  # delta = 6 - 3 - 0 = 3, Rule 1: delta 3 ≤ 5
                            7: 4,  # delta = 7 - 3 - 0 = 4, Rule 1: delta 4 ≤ 5
                            8: 5,  # delta = 8 - 3 - 0 = 5, Rule 1: delta 5 ≤ 5
                            9: 6,  # delta = 6 - 0 = 6, Rule 3: pronic number (2*3)
                            10: 6,  # delta = 10 - 3 - 0 = 7
                            11: 6,  # delta = 11 - 3 - 0 = 8
                            12: 9,  # delta = 9 - 0 = 9, Rule 2: perfect square (3^2)
                            13: 9,  # delta = 13 - 3 - 0 = 10
                            14: 9,  # delta = 14 - 3 - 0 = 11
                            15: 12,  # delta = 15 - 3 - 0 = 12, Rule 3: pronic number (3*4)
                            16: 12,  # delta = 16 - 3 - 0 = 13
                            17: 12,  # delta = 17 - 3 - 0 = 14
                            18: 12,  # delta = 18 - 3 - 0 = 15
                            19: 16,  # delta = 19 - 3 - 0 = 16, Rule 2: perfect square (4^2)
                            20: 16,  # delta = 20 - 3 - 0 = 17
                            21: 16,  # delta = 21 - 3 - 0 = 18
                            22: 16,  # delta = 22 - 3 - 0 = 19
                            23: 20,  # delta = 23 - 3 - 0 = 20, Rule 3: pronic number (4*5)
                            24: 20,  # delta = 24 - 3 - 0 = 21
                            25: 20,  # delta = 25 - 3 - 0 = 22
                            26: 20,  # delta = 26 - 3 - 0 = 23
                            27: 20,  # delta = 27 - 3 - 0 = 24
                            28: 25,  # delta = 28 - 3 - 0 = 25, Rule 2: perfect square (5^2)
                            29: 25,  # delta = 29 - 3 - 0 = 26
                            30: 25,  # delta = 30 - 3 - 0 = 27
                        }[i]
                    ),
                ),
            )
            for i in range(1, 31)
        ],
    )
