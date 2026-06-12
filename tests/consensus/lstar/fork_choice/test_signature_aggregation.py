"""Signature Aggregation Tests for Fork Choice"""

import pytest

from consensus_testing import (
    AggregatedAttestationCheck,
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
)
from lean_spec.spec.forks import Interval, Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


@pytest.mark.real_crypto(smoke=True)
def test_multiple_attestations_same_target_merge_into_one(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Two attestations in the known pool sharing one target get merged
    into a single aggregation.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - block_2 includes V0, V1's votes for block_1.
    - block_2 includes V2, V3's votes for block_1.
    - both votes carry identical attestation data.

    When
    ----
    - block_2 is added with both votes.

    Then
    ----
    - block_2 holds 1 aggregated attestation.
    - that aggregation covers V0, V1, V2, V3.
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
                            validator_indices=[ValidatorIndex(0), ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2), ValidatorIndex(3)],
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


@pytest.mark.real_crypto(smoke=True)
def test_overlapping_proofs_same_target_recursively_merge_into_one(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Two overlapping proofs for one target fold into a single in-block attestation.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis -> block_1(1)
    - one proof covers V0, V1, V2 targeting block_1.
    - one proof covers V1, V2, V3 targeting block_1.
    - the two proofs overlap on V1, V2.
    - both proofs carry identical attestation data.
    - both proofs wait unmerged in the known pool.

    When
    ----
    - block_2 is built on block_1, carrying no votes of its own.

    Then
    ----
    - block_2 holds 1 aggregated attestation.
    - that aggregation covers V0, V1, V2, V3.
    - head is block_2.
    - head is at slot 2.

    Timing
    ------
    - the proofs are gossipped at slot 1, interval 3.
    - interval 3 is past the aggregate phase.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            TickStep(interval=int(Interval.from_slot(Slot(1))) + 3),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(1),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(1),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
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
    Attestations with different targets stay separate aggregations.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2) -> block_3(3)
    - block_3 includes V0, V1's votes for block_1.
    - block_3 includes V2, V3's votes for block_2.
    - the two votes target different blocks.

    When
    ----
    - block_3 is added with both votes.

    Then
    ----
    - block_3 holds 2 aggregated attestations.
    - one aggregation covers V0, V1 targeting block_1.
    - one aggregation covers V2, V3 targeting block_2.
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
                            validator_indices=[ValidatorIndex(0), ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2), ValidatorIndex(3)],
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
    A block carrying votes for two different targets keeps them in two aggregations.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2) -> block_3(3) -> block_4(4)
    - block_4 includes V0, V1's votes for block_2.
    - block_4 includes V2, V3's votes for block_3.
    - the two votes target blocks at different chain positions.

    When
    ----
    - block_4 is added with both votes.

    Then
    ----
    - block_4 holds 2 aggregated attestations.
    - one aggregation covers V0, V1 targeting block_2.
    - one aggregation covers V2, V3 targeting block_3.
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
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0), ValidatorIndex(1)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2), ValidatorIndex(3)],
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
    All validators voting for one target fold into a single aggregation.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - block_2 includes V0, V1, V2, V3's votes for block_1.

    When
    ----
    - block_2 is added with the votes.

    Then
    ----
    - block_2 holds 1 aggregated attestation.
    - that aggregation covers V0, V1, V2, V3.
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
                            validator_indices=[
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
