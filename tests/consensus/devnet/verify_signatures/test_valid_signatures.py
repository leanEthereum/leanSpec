"""Valid signature verification tests"""

import pytest
from consensus_testing import (
    BlockSpec,
    SignedAttestationSpec,
    VerifySignaturesTestFiller,
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.xmss.interface import PROD_SIGNATURE_SCHEME
from lean_spec.types import Uint64

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
        anchor_state=generate_pre_state(num_validators=2, scheme=PROD_SIGNATURE_SCHEME),
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
    - 2 additional attestations from validators 0 and 2 (in addition to proposer)
    - Verifies that all signatures are generated correctly

    Expected Behavior
    -----------------
    1. Proposer's signature in SignedBlockWithAttestation can be verified against
       the validator's pubkey in the state
    2. Attester's signatures in SignedBlockWithAttestation can be verified against
       the validator's pubkey in the state

    Why This Matters
    ----------------
    This test verifies multi-validator signature scenarios:
    - Multiple XMSS keys are generated for different validators
    - Attestations from non-proposer validators are correctly verified
    - Signature aggregation works with multiple attestations (signature positions are correct)
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=3, scheme=PROD_SIGNATURE_SCHEME),
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
