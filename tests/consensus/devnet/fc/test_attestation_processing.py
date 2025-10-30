"""
Attestation Processing Through Block Proposer Mechanism
========================================================

Overview
--------
Tests proposer attestations in the devnet fork.
Each block's proposer creates an attestation that flows through a two-stage pipeline.

The Attestation Pipeline
-------------------------
Attestations flow through two dictionaries, both keyed by validator index:

**Stage 1: latest_new_attestations**
    - New attestations enter here immediately after block processing.
    - Holds the current slot's proposer attestation.

**Stage 2: latest_known_attestations**
    - Accepted attestations that contribute to fork choice weights.
    - Updated by the interval tick system between slots.

Key Behaviors
-------------
**Migration**: Between blocks, attestations move from new → known via interval ticks.

**Superseding**:
    - Newer attestation from the same validator replaces older one.
    - Only the most recent attestation per validator is retained.

**Accumulation**: Attestations from different validators coexist across both dictionaries.
"""

import pytest
from consensus_testing import (
    AttestationCheck,
    AttestationStep,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)

from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Checkpoint,
    SignedAttestation,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_proposer_attestation_appears_in_latest_new(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Proposer attestation appears in latest_new after block processing.

    Scenario
    --------
    Process one block at slot 1 (proposer: validator 1).

    Expected:
        - validator 1's attestation has correct slot and checkpoint slots

    Why This Matters
    ----------------
    New proposer attestations enter the pipeline through `latest_new_attestations`,
    not directly into `latest_known_attestations`.

    This baseline test verifies the entry point of the attestation pipeline.
    All new attestations must enter through the "new" stage before graduating to "known".
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            head_slot=Slot(1),
                            source_slot=Slot(0),  # Genesis
                            target_slot=Slot(1),
                            location="new",
                        ),
                    ],
                ),
            ),
        ],
    )


def test_attestation_superseding_same_validator(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Newer attestation from same validator supersedes older attestation.

    Scenario
    --------
    Process blocks at slots 1 and 5 (same proposer: validator 1).

    Expected:
        - After slot 1: validator 1 attests to slot 1
        - After slot 5: validator 1 attests to slot 5 (supersedes slot 1)

    Why This Matters
    ----------------
    With round-robin proposer selection, slots 1 and 5 use the same validator.

    When that validator proposes again, their newer attestation supersedes the older one.
    Both dictionaries are keyed by validator index, so only the most recent
    attestation per validator is retained.

    Key insight: Attestations accumulate across validators but supersede within validators.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            head_slot=Slot(1),
                            source_slot=Slot(0),
                            target_slot=Slot(1),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_checks=[
                        # Validator 1's newer attestation (superseded the old one)
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(5),
                            head_slot=Slot(5),
                            target_slot=Slot(5),
                            location="new",
                        ),
                    ],
                ),
            ),
        ],
    )


def test_attestations_move_to_known_between_blocks(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestations move from latest_new to latest_known between blocks.

    Scenario
    --------
    Process blocks at slots 1 and 2 (different proposers: validators 1 and 2).

    Expected:
        - After slot 1: new attestations = 1, known attestations = 0
        - After slot 2: new attestations = 1, known attestations = 1
        - Validator 1's attestation moved to known with correct checkpoints
        - Validator 2's attestation in new with correct checkpoints

    Why This Matters
    ----------------
    The interval tick system drives attestation migration between slots.

    Before processing the next block, interval ticks move all attestations from
    new → known and clear the new dictionary. Then the next block's proposer
    attestation enters the now-empty new dictionary.

    This creates the attestation pipeline:
    - Enter via new (arrivals)
    - Graduate to known (accepted for fork choice)
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            head_slot=Slot(1),
                            source_slot=Slot(0),
                            target_slot=Slot(1),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_checks=[
                        # Validator 1's attestation migrated to known
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            head_slot=Slot(1),
                            source_slot=Slot(0),
                            target_slot=Slot(1),
                            location="known",  # Now in known!
                        ),
                        # Validator 2's new attestation
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            attestation_slot=Slot(2),
                            head_slot=Slot(2),
                            source_slot=Slot(1),
                            target_slot=Slot(2),
                            location="new",
                        ),
                    ],
                ),
            ),
        ],
    )


def test_attestation_accumulation_full_validator_set(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    All validators contribute attestations across both dictionaries.

    Scenario
    --------
    Process blocks at slots 1, 2, 3, 4 (complete validator rotation).

    Expected:
        - After slot 1:  new attestations = 1, known attestations = 0
        - After slot 2:  new attestations = 1, known attestations = 1
        - After slot 3:  new attestations = 1, known attestations = 2
        - After slot 4:  new attestations = 1, known attestations = 3  (total: 4 validators)

    Why This Matters
    ----------------
    With 4 validators and consecutive blocks, each validator proposes once.

    Attestations accumulate across both dictionaries:
    - new: current slot's proposer
    - known: all previous proposers

    The total (new + known) equals the number of unique validators who proposed.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            target_slot=Slot(1),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            location="known",  # Moved to known
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            attestation_slot=Slot(2),
                            target_slot=Slot(2),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            attestation_slot=Slot(2),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            attestation_slot=Slot(3),
                            target_slot=Slot(3),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4)),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    attestation_checks=[
                        # All 4 validators now have attestations
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            attestation_slot=Slot(2),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            attestation_slot=Slot(3),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            attestation_slot=Slot(4),
                            target_slot=Slot(4),
                            location="new",
                        ),
                    ],
                ),
            ),
        ],
    )


def test_slot_gaps_with_attestation_superseding(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation superseding works correctly with missed slots.

    Scenario
    --------
    Process blocks at slots 1, 3, 5, 7 (skipping even slots).
    Proposers: validators 1, 3, 1, 3 (same validators repeat).

    Expected:
        - After slot 1:  Validator 1 attests
        - After slot 3:  Validator 3 attests, validator 1 moved to known
        - After slot 5:  Validator 1 attests again (supersedes old), validator 3 in known
        - After slot 7:  Validator 3 attests again (supersedes old), validator 1 in known

    Why This Matters
    ----------------
    Missed slots are normal when proposers fail to produce blocks.

    With non-contiguous slots, round-robin means validators propose multiple times.
    When they do, their newer attestations supersede their older ones.

    Total count stays at 2 (unique validators) throughout slots 5-7.

    This confirms attestation processing and superseding work correctly with slot gaps
    across both dictionaries.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            target_slot=Slot(1),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            location="known",  # Moved to known
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            attestation_slot=Slot(3),
                            target_slot=Slot(3),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            attestation_slot=Slot(3),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(5),  # Newer attestation superseded slot 1
                            target_slot=Slot(5),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7)),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(5),  # Latest from validator 1
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            attestation_slot=Slot(7),  # Newer attestation superseded slot 3
                            target_slot=Slot(7),
                            location="new",
                        ),
                    ],
                ),
            ),
        ],
    )


def test_extended_chain_attestation_superseding_pattern(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation superseding pattern over two complete validator rotations.

    Scenario
    --------
    Process blocks at slots 1-8 (two complete validator rotations).

    Phase 1 (slots 1-4): Accumulation
        Validators each propose once, attestations accumulate to 4 total.

    Phase 2 (slots 5-8): Steady State
        Validators propose again, newer attestations supersede older ones.
        Total stays at 4, composition changes.

    Expected:
        - After slot 4:  All 4 validators have attestations (v0 in new, v1-v3 in known)
        - After slot 5:  Validator 1 supersedes their slot 1 attestation
        - After slot 8:  All validators have their latest attestations from slots 5-8

    Why This Matters
    ----------------
    The system reaches steady state: one attestation per validator.

    As each validator proposes again, their new attestation supersedes their old one.
    The count remains constant (4), but the composition updates.

    This confirms superseding maintains correct state over time with no attestation
    leaks or unbounded growth.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            attestation_slot=Slot(2),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            attestation_slot=Slot(2),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            attestation_slot=Slot(3),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4)),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(1),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            attestation_slot=Slot(2),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            attestation_slot=Slot(3),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            attestation_slot=Slot(4),
                            location="new",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_checks=[
                        # Validator 1's newer attestation supersedes slot 1
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(5),
                            location="new",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            attestation_slot=Slot(4),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            attestation_slot=Slot(2),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            attestation_slot=Slot(3),
                            location="known",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(6)),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    attestation_checks=[
                        # Validator 2's newer attestation supersedes slot 2
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            attestation_slot=Slot(6),
                            location="new",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            attestation_slot=Slot(4),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(5),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            attestation_slot=Slot(3),
                            location="known",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7)),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    attestation_checks=[
                        # Validator 3's newer attestation supersedes slot 3
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            attestation_slot=Slot(7),
                            location="new",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            attestation_slot=Slot(4),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(5),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            attestation_slot=Slot(6),
                            location="known",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(8)),
                checks=StoreChecks(
                    head_slot=Slot(8),
                    attestation_checks=[
                        # Validator 0's newer attestation supersedes slot 4
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            attestation_slot=Slot(8),
                            location="new",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            attestation_slot=Slot(5),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            attestation_slot=Slot(6),
                            location="known",
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            attestation_slot=Slot(7),
                            location="known",
                        ),
                    ],
                ),
            ),
        ],
    )
