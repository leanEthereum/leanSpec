"""Invalid signature verification tests"""

import pytest
from consensus_testing import (
    BlockSpec,
    SignedAttestationSpec,
    VerifySignaturesTestFiller,
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Uint64

pytestmark = pytest.mark.valid_until("Devnet")


def test_invalid_signature(
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


# TODO: Add test for mixed valid and invalid signatures
# This test currently fails because attester-signature verification relies on the
# aggregated multisig proof, but multisig aggregation/verification runs in test_mode.
# Since the proposer signature is valid and verified individually, the block is not rejected.”
# def test_mixed_valid_invalid_signatures(
#     verify_signatures_test: VerifySignaturesTestFiller,
# ) -> None:
#     """
#     Test that signature verification catches invalid signatures among valid ones.

#     Scenario
#     --------
#     - Single block at slot 1
#     - Proposer attestation from validator 1
#     - 2 non-proposer attestations from validators 0 and 2
#     - Total: 3 signatures, middle attestation (validator 2) has an invalid signature

#     Expected Behavior
#     -----------------
#     1. The SignedBlockWithAttestation is rejected due to 1 invalid signature

#     Why This Matters
#     ----------------
#     This test verifies that signature verification:
#     - Checks every signature individually, not just the first or last
#     - Cannot be bypassed by surrounding invalid signatures with valid ones
#     - Properly fails even when some signatures are valid
#     - Validates all attestations in the block
#     """
#     verify_signatures_test(
#         anchor_state=generate_pre_state(num_validators=3),
#         block=BlockSpec(
#             slot=Slot(1),
#             attestations=[
#                 SignedAttestationSpec(
#                     validator_id=Uint64(0),
#                     slot=Slot(1),
#                     target_slot=Slot(0),
#                     target_root_label="genesis",
#                 ),
#                 SignedAttestationSpec(
#                     validator_id=Uint64(2),
#                     slot=Slot(1),
#                     target_slot=Slot(0),
#                     target_root_label="genesis",
#                     valid_signature=False,
#                 ),
#             ],
#         ),
#         expect_exception=AssertionError,
#     )
