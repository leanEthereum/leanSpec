"""Signature Aggregation Tests for Fork Choice"""

import pytest
from consensus_testing import (
    AggregatedAttestationCheck,
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_multiple_specs_same_target_merge_into_one(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Multiple attestation specs with identical data merge into single aggregation.

    Scenario
    --------
    Block at slot 2 includes:
    - Validators 0, 1 attesting to block 1
    - Validators 2, 3 attesting to block 1 (same target)

    Expected
    --------
    - 1 aggregated attestation (merged)
    - Covers all validators {0, 1, 2, 3}
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0), ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(2), ValidatorIndex(3)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    block_attestation_count=1,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={0, 1, 2, 3},
                            attestation_slot=Slot(1),
                            target_slot=Slot(1),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_different_targets_create_separate_aggregations(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestations with different targets stay separate.

    Scenario
    --------
    Block at slot 3 includes:
    - Validators 0, 1 targeting block 1
    - Validators 2, 3 targeting block 2

    Expected
    --------
    - 2 separate aggregated attestations
    - Cannot merge because different AttestationData
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0), ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(2), ValidatorIndex(3)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    block_attestation_count=2,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={0, 1},
                            attestation_slot=Slot(1),
                            target_slot=Slot(1),
                        ),
                        AggregatedAttestationCheck(
                            participants={2, 3},
                            attestation_slot=Slot(2),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_mixed_attestations_multiple_targets_and_validators(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Complex scenario with mixed attestations from different sources and targets.

    Scenario
    --------
    Block at slot 4 includes attestations for both block 2 and block 3:
    - Validators 0, 1 attest to block 2 (older)
    - Validators 2, 3 attest to block 3 (newer)

    Expected
    --------
    - 2 separate aggregations (different targets)
    - Each aggregation has correct participants
    - Demonstrates handling attestations for multiple chain positions
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), label="block_3"),
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    attestations=[
                        # Attestations for older block
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0), ValidatorIndex(1)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                        # Attestations for newer block
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(2), ValidatorIndex(3)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="block_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    block_attestation_count=2,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={0, 1},
                            attestation_slot=Slot(2),
                            target_slot=Slot(2),
                        ),
                        AggregatedAttestationCheck(
                            participants={2, 3},
                            attestation_slot=Slot(3),
                            target_slot=Slot(3),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_all_validators_attest_in_single_aggregation(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Maximum aggregation: all 4 validators in a single attestation.

    Scenario
    --------
    All validators attest to block 1 in block 2.

    Expected
    --------
    - Single aggregated attestation
    - All 4 validators as participants
    - Demonstrates complete coverage in one proof
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                                ValidatorIndex(3),
                            ],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    block_attestation_count=1,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={0, 1, 2, 3},
                            attestation_slot=Slot(1),
                            target_slot=Slot(1),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_auto_collect_proposer_attestations(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Automatically collect previous proposers' attestations into block body.

    Scenario
    --------
    With automatic attestation collection enabled:
    - Block 1: proposer 1 attests (attestation goes to Store)
    - Block 2: auto-collects proposer 1's attestation into block body

    Expected
    --------
    Without explicit attestation specs, blocks automatically include
    attestations from previous proposers whose signatures are available
    and whose source matches the current justified checkpoint.

    Note: Auto-collection only includes attestations whose source matches
    the post-state's latest_justified checkpoint. Proposer attestations
    reference their parent as source, which must match for inclusion.
    """
    fork_choice_test(
        steps=[
            # Block 1: Proposer 1 attests (goes to the store gossiped signatures)
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    block_attestation_count=0,
                ),
            ),
            # Block 2: Auto-collect proposer 1's attestation
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    label="block_2",
                    include_store_attestations=True,
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    # Proposer 1's attestation should be auto-collected
                    block_attestation_count=1,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={1},
                            attestation_slot=Slot(1),
                            target_slot=Slot(1),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_auto_collect_combined_with_explicit_attestations(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Combine auto-collection with explicit attestation specs.

    Scenario
    --------
    Block 2 uses both mechanisms:
    - Auto-collection gathers proposer 1's attestation from Store
    - Explicit spec adds validators 0 and 3

    Expected
    --------
    Block body contains merged attestation from all sources:
    - Proposer 1's attestation (auto-collected)
    - Validators 0 and 3 (explicitly specified)
    - All merged into single aggregation (same target)
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    include_store_attestations=True,
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0), ValidatorIndex(3)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    # All attestations merged: proposer 1 + explicit {0, 3}
                    block_attestation_count=1,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={0, 1, 3},
                            attestation_slot=Slot(1),
                            target_slot=Slot(1),
                        ),
                    ],
                ),
            ),
        ],
    )
