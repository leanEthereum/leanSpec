"""Basic signature generation tests"""

import pytest
from consensus_testing import (
    BlockSpec,
    SignatureTestFiller,
    SignedAttestationSpec,
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Uint64

pytestmark = pytest.mark.valid_until("Devnet")


def test_proposer_signature(
    signature_test: SignatureTestFiller,
) -> None:
    """
    Test basic signature generation for a block with only the proposer attestation.

    Scenario
    --------
    - Single block at slot 1
    - No additional attestations (only proposer attestation)

    Expected Behavior
    -----------------
    1. Proposer's signature in SignedBlockWithAttestation can be verified successfully

    Why This Matters
    ----------------
    This is the most basic signature generation test. It verifies:
    - XMSS key generation works
    - Block building produces correct structure (TODO: use the spec's block building function)
    - Proposer attestation is created properly
    - Signature aggregation includes proposer signature
    - Output serialization works for test vectors

    This serves as a foundation test for the signature fixture.
    """
    signature_test(
        anchor_state=generate_pre_state(num_validators=1),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[],
        ),
    )

def test_proposer_and_attester_signatures(
    signature_test: SignatureTestFiller,
) -> None:
    """
    Test signature generation for a block with proposer and attester signatures.

    Scenario
    --------
    - Single block at slot 1
    - 3 validators in the genesis state
    - 2 additional attestations from validators 0 and 2 (in addition to proposer)
    - Verifies that all signatures are generated correctly

    Expected Behavior
    -----------------
    1. Block is created with correct slot
    2. Proposer attestation is generated (from validator 1)
    3. Two attester signatures are included (from validators 0 and 2)
    4. All three signatures are properly aggregated
    5. Output contains a valid SignedBlockWithAttestation with 3 signatures

    Why This Matters
    ----------------
    This test verifies multi-validator signature scenarios:
    - Multiple XMSS keys are generated for different validators
    - Attestations from non-proposer validators are correctly signed
    - Signature aggregation works with multiple attestations
    - Block body contains the attestations
    - All signatures can be verified independently

    This is crucial for testing realistic blocks where multiple validators
    attest to the same block, which is the common case in consensus.
    """
    signature_test(
        anchor_state=generate_pre_state(num_validators=3),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                SignedAttestationSpec(
                    validator_id=Uint64(0),
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                ),
                SignedAttestationSpec(
                    validator_id=Uint64(2),
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                ),
            ],
        ),
    )
