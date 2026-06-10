"""Signature verification pins the off-by-one at the proposer and attester registry bounds."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    ExpectedRejection,
    SetProposerIndex,
    VerifySignaturesTestFiller,
    generate_pre_state,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


def test_proposer_index_at_registry_size_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A proposer index exactly equal to the registry size is rejected.

    Given
    -----
    - a registry of 4 validators (indices 0 through 3).
    - a block at slot 1 signed honestly by the in-range proposer.
    - the proposer index is then rewritten to 4.
    - index 4 is the first index past the registry.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification is rejected as an out-of-range proposer index.
    - the bound is strict less-than, so the registry size itself is out of range.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[],
        ),
        tamper=SetProposerIndex(proposer_index=ValidatorIndex(4)),
        expected_rejection=ExpectedRejection(reason=RejectionReason.PROPOSER_INDEX_OUT_OF_RANGE),
    )


def test_proposer_index_at_last_registry_slot_accepted(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A proposer index one below the registry size is accepted.

    Given
    -----
    - a registry of 4 validators (indices 0 through 3).
    - a block at slot 3 proposed and signed honestly by V3.
    - V3 is the round-robin proposer at slot 3 (3 modulo 4).
    - index 3 is the last index inside the registry.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification passes for the last in-range proposer.
    - the bound is strict less-than, not less-than-or-equal.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(3),
            proposer_index=ValidatorIndex(3),
            attestations=[],
        ),
    )


def test_attester_index_at_registry_size_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    An aggregate naming a validator index equal to the registry size is rejected.

    Given
    -----
    - a registry of 4 validators (indices 0 through 3).
    - an aggregate naming validator index 4.
    - index 4 is the first index past the registry.
    - the aggregate carries an invalid signature, so no signing is attempted for the missing index.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification is rejected as an out-of-range validator index.
    - the bound is strict less-than, so the registry size itself is out of range.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(2),
            attestations=[
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(4)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                    valid_signature=False,
                ),
            ],
        ),
        expected_rejection=ExpectedRejection(reason=RejectionReason.VALIDATOR_INDEX_OUT_OF_RANGE),
    )


def test_attester_index_at_last_registry_slot_accepted(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    An aggregate naming the last in-range validator index is accepted.

    Given
    -----
    - a registry of 4 validators (indices 0 through 3).
    - a block at slot 1.
    - an aggregate from V3 alone targeting genesis.
    - index 3 is the last index inside the registry.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification passes for the last in-range attester.
    - the bound is strict less-than, not less-than-or-equal.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(3)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                ),
            ],
        ),
    )
