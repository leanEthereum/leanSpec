"""Basic signature generation tests"""

import pytest
from consensus_testing import (
    BlockSpec,
    SignatureTestFiller,
    SignedAttestationSpec,
    generate_pre_state,
)

from lean_spec.subspecs.containers.attestation import Attestation, AttestationData
from lean_spec.subspecs.containers.block.block import (
    Block,
    BlockBody,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import Attestations, BlockSignatures
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss.constants import PROD_CONFIG
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.types import HashDigestList, HashTreeOpening, Randomness
from lean_spec.types import Bytes32, Uint64

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


def test_invalid_signature(
    signature_test: SignatureTestFiller,
) -> None:
    """
    Test that invalid signatures are properly rejected during verification.

    Scenario
    --------
    - Single block at slot 1
    - Override the signature with an invalid dummy signature
    - Verification should fail

    Expected Behavior
    -----------------
    1. Block is created with correct slot
    2. Signature is overridden with an invalid one
    3. verify_signatures() catches the invalid signature
    4. No output is written (since valid=False)

    Why This Matters
    ----------------
    This test verifies the negative case:
    - Signature verification actually validates cryptographic correctness
    - Invalid signatures are caught, not silently accepted
    - The verification process has real security value
    - Clients can trust that passing verification means valid signatures

    This is crucial for security - verification must reject invalid signatures,
    not just check structural correctness.
    """

    invalid_signature = Signature(
        path=HashTreeOpening(siblings=HashDigestList(data=[])),
        rho=Randomness(data=[Fp(0) for _ in range(PROD_CONFIG.RAND_LEN_FE)]),
        hashes=HashDigestList(data=[]),
    )

    signature_test(
        anchor_state=generate_pre_state(num_validators=1),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[],
        ),
        override_signature=BlockSignatures(data=[invalid_signature]),
        expect_exception=AssertionError,
    )


def test_mixed_valid_invalid_signatures(
    signature_test: SignatureTestFiller,
) -> None:
    """
    Test that signature verification catches invalid signatures among valid ones.

    Scenario
    --------
    - Block at slot 1 with 3 validators
    - 2 attestations from validators 0 and 2
    - Middle attestation (validator 2) has an invalid signature
    - Plus the proposer attestation (validator 1)
    - Total: 3 signatures, middle one invalid

    Expected Behavior
    -----------------
    1. Block is created with correct slot
    2. Three attestations are created (validator 0, 2, and proposer 1)
    3. Validator 2's attestation gets an invalid dummy signature
    4. verify_signatures() catches the invalid signature
    5. SignedBlockWithAttestation is still output for testing

    Why This Matters
    ----------------
    This test verifies that signature verification:
    - Checks every signature individually, not just the first or last
    - Cannot be bypassed by surrounding invalid signatures with valid ones
    - Properly fails even when some signatures are valid
    - Validates all attestations in the block

    This ensures that clients cannot accidentally accept partially invalid
    blocks by only checking a subset of signatures.
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
                    valid_signature=False,
                ),
            ],
        ),
        expect_exception=AssertionError,
    )
