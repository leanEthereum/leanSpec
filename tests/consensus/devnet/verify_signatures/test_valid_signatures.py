"""Valid signature verification tests"""

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
                    validator_ids=[Uint64(0), Uint64(2)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                ),
            ],
        ),
    )
