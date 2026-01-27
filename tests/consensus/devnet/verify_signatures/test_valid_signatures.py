"""Valid signature verification tests"""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    VerifySignaturesTestFiller,
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_proposer_signature(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    Test valid proposer signature in SignedBlockWithAttestation.

    Scenario
    --------
    - Single block at slot 1
    - No additional attestations (only proposer attestation)

    Expected Behavior
    -----------------
    1. Proposer's signature in SignedBlockWithAttestation can be verified against
       the validator's pubkey in the state

    Why This Matters
    ----------------
    This is the most basic signature generation test. It verifies:
    - XMSS key generation works
    - Signature aggregation includes proposer signature
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=2),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[],
        ),
    )


def test_proposer_and_attester_signatures(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    Test valid proposer and attester signatures in SignedBlockWithAttestation.

    Scenario
    --------
    - Single block at slot 1
    - 3 validators in the genesis state
    - Aggregated attestation from validators 0 and 2 (in addition to proposer)
    - Verifies that all signatures are generated and aggregated correctly

    Expected Behavior
    -----------------
    1. Proposer's signature in SignedBlockWithAttestation can be verified against
       the validator's pubkey in the state
    2. Aggregated attestation signatures can be verified against the validators'
       pubkeys in the state

    Why This Matters
    ----------------
    This test verifies multi-validator signature aggregation:
    - Multiple XMSS keys are generated for different validators
    - Attestations with same data are properly aggregated
    - leanVM signature aggregation works with multiple validators
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=3),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(0), ValidatorIndex(2)],
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
    Test signature aggregation when all validators attest.

    Scenario
    --------
    - Block at slot 1 with 4 validators
    - Attestations from validators 0, 2, 3 (proposer 1 is implicit)

    Expected Behavior
    -----------------
    - All 4 validator signatures are properly aggregated
    - Verification succeeds for the complete validator set

    Why This Matters
    ----------------
    Maximum coverage scenario: all validators participate.
    This tests aggregation at full capacity for a small validator set.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(0), ValidatorIndex(2), ValidatorIndex(3)],
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
    Test signature generation for single validator attestation.

    Scenario
    --------
    - Block at slot 1 with 4 validators
    - Only one validator (0) provides an attestation

    Expected Behavior
    -----------------
    - Single validator signature is properly generated
    - Aggregation handles the minimal case correctly

    Why This Matters
    ----------------
    Edge case: minimal attestation coverage.
    Verifies aggregation works with single-validator input.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(0)],
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
    Test that separate attestation specs with same data get aggregated.

    Scenario
    --------
    - Block at slot 1 with 4 validators
    - Two separate attestation specs, both targeting genesis
        - Group 1: validators 0, 2
        - Group 2: validator 3

    Expected Behavior
    -----------------
    - Attestations with identical data should be merged
    - All signatures verified correctly

    Why This Matters
    ----------------
    Tests the aggregation logic when multiple specs target the same data.
    Real-world scenario: validators attest independently to the same target.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(0), ValidatorIndex(2)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                ),
                AggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(3)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                ),
            ],
        ),
    )
