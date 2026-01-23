"""Invalid signature verification tests"""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    VerifySignaturesTestFiller,
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Uint64

pytestmark = pytest.mark.valid_until("Devnet")


def test_invalid_proposer_signature(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    Test that invalid signatures are properly rejected during verification.

    Scenario
    --------
    - Single block at slot 1
    - Proposer attestation has an invalid signature
    - No additional attestations (only proposer attestation)

    Expected Behavior
    -----------------
    1. Proposer's signature in SignedBlockWithAttestation is rejected

    Why This Matters
    ----------------
    This test verifies the negative case:
    - Signature verification actually validates cryptographic correctness
      not just structural correctness.
    - Invalid signatures are caught, not silently accepted
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=1),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[],
            valid_signature=False,
        ),
        expect_exception=AssertionError,
    )


def test_invalid_aggregated_attestation_signature(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    Test that invalid aggregated attestation signatures are properly rejected.

    Scenario
    --------
    - Single block at slot 1
    - Proposer attestation from validator 1 (valid)
    - Two aggregated attestations with different data:
      - One from validator 0 with valid signature
      - One from validator 2 with invalid signature

    Expected Behavior
    -----------------
    1. The SignedBlockWithAttestation is rejected due to invalid aggregated signature

    Why This Matters
    ----------------
    This test verifies that aggregated signature verification:
    - Properly validates leanVM aggregated proofs for each attestation group
    - Rejects blocks containing any invalid aggregated attestation signature
    - Works correctly even when some attestations have valid signatures
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=3),
        block=BlockSpec(
            slot=Slot(2),
            attestations=[
                # Valid aggregated attestation
                AggregatedAttestationSpec(
                    validator_ids=[Uint64(0)],
                    slot=Slot(2),
                    target_slot=Slot(1),
                    target_root_label="genesis",
                    valid_signature=True,
                ),
                # Invalid aggregated attestation (different target to force separate aggregation)
                AggregatedAttestationSpec(
                    validator_ids=[Uint64(2)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                    valid_signature=False,
                ),
            ],
        ),
        expect_exception=AssertionError,
    )
