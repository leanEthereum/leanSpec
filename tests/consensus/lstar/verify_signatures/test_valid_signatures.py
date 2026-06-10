"""Signature verification accepts blocks with valid proposer and aggregated attester signatures."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    VerifySignaturesTestFiller,
    generate_pre_state,
)
from lean_spec.spec.forks import Slot, ValidatorIndex

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


def test_proposer_signature(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A block carrying only a valid proposer signature verifies.

    Given
    -----
    - a registry of 2 validators.
    - a block at slot 1 with no attestations.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification passes against the proposer public key in the state.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=2),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[],
        ),
    )


@pytest.mark.real_crypto(smoke=True)
def test_proposer_and_attester_signatures(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A block carrying a valid proposer signature and an aggregated attestation verifies.

    Given
    -----
    - a registry of 3 validators.
    - a block at slot 1.
    - an aggregate from V0 and V2 targeting genesis.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification passes for the proposer signature.
    - verification passes for the aggregated attester signatures.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=3),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0), ValidatorIndex(2)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                ),
            ],
        ),
    )


def test_all_four_validators_attesting(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A block in which every validator participates verifies.

    Given
    -----
    - a registry of 4 validators.
    - a block at slot 1.
    - an aggregate from V0, V2, and V3, with the proposer V1 implicit.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification passes for the complete validator set.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0), ValidatorIndex(2), ValidatorIndex(3)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                ),
            ],
        ),
    )


def test_single_validator_attestation(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A block whose only attestation comes from one validator verifies.

    Given
    -----
    - a registry of 4 validators.
    - a block at slot 1.
    - an aggregate from V0 alone.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification passes for the single-validator aggregate.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                ),
            ],
        ),
    )


def test_multiple_attestation_groups_same_data(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    Two aggregates over the same data merge into one verified group.

    Given
    -----
    - a registry of 4 validators.
    - a block at slot 1.
    - an aggregate from V0 and V2 targeting genesis.
    - a second aggregate from V3 targeting the same genesis data.

    When
    ----
    - signature verification runs.

    Then
    ----
    - the two aggregates merge because they share the same data.
    - verification passes for the merged group.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0), ValidatorIndex(2)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                ),
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(3)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                ),
            ],
        ),
    )
