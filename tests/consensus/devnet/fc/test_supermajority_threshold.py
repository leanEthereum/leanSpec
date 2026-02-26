"""Strict Supermajority Threshold for Justification.

Verifies the strict supermajority requirement: exactly 2/3 of validators
is NOT sufficient for justification — strictly more than 2/3 is required.

The justification check uses `3 * attesting > 2 * total` (strict inequality).
"""

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


def test_exact_two_thirds_does_not_justify(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Exactly 2/3 of validators attesting does NOT justify a block.

    Scenario
    --------
    6 validators, 4 attesting (4/6 = 2/3 exactly).

    The strict supermajority check requires `3 * attesting > 2 * total`:
    - 3 * 4 = 12, 2 * 6 = 12 → 12 > 12 is false → no justification.

    Chain:
        genesis → block_1 (slot 1) → block_2 (slot 2) → block_3 (slot 3)

    block_3 carries an aggregated attestation from validators [0, 1, 2, 3]
    targeting block_2 at slot 2. Despite reaching the 2/3 threshold exactly,
    the latest justified slot must remain at genesis (slot 0).
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="block_2",
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                                ValidatorIndex(3),
                            ],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    latest_justified_slot=Slot(0),  # Still genesis — NOT justified
                ),
            ),
        ],
    )


def test_above_two_thirds_justifies(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Strictly more than 2/3 of validators attesting DOES justify a block.

    Scenario
    --------
    6 validators, 5 attesting (5/6 ≈ 83.3% > 2/3).

    The strict supermajority check requires `3 * attesting > 2 * total`:
    - 3 * 5 = 15, 2 * 6 = 12 → 15 > 12 is true → justification succeeds.

    Chain:
        genesis → block_1 (slot 1) → block_2 (slot 2) → block_3 (slot 3)

    block_3 carries an aggregated attestation from validators [0, 1, 2, 3, 4]
    targeting block_2 at slot 2. This exceeds the strict 2/3 threshold,
    so block_2 becomes justified.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="block_2",
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                                ValidatorIndex(3),
                                ValidatorIndex(4),
                            ],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    latest_justified_slot=Slot(2),  # Justified!
                    latest_justified_root_label="block_2",
                ),
            ),
        ],
    )
