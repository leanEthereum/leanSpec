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

from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


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
                block=BlockSpec(
                    slot=Slot(1),
                    label="block_1",
                ),
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
                block=BlockSpec(
                    slot=Slot(1),
                    label="block_1",
                ),
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
