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
    - 10 validators in the genesis state
    - No additional attestations (only proposer attestation)
    - Verifies that signatures are generated correctly

    Expected Behavior
    -----------------
    1. Block is created with correct slot
    2. Proposer attestation is generated
    3. All signatures are properly created
    4. Output contains a valid SignedBlockWithAttestation

    Why This Matters
    ----------------
    This is the most basic signature generation test. It verifies:
    - XMSS key generation works
    - Block building produces correct structure
    - Proposer attestation is created properly
    - Signature aggregation includes proposer signature
    - Output serialization works for test vectors

    This serves as a foundation test for the signature fixture.
    """
    signature_test(
        anchor_state=generate_pre_state(num_validators=1),
        block=BlockSpec(slot=Slot(1)),
        attestations=[],
    )
