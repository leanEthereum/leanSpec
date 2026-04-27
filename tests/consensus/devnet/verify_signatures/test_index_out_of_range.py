"""Signature Verification: Out-of-Range Attestation Validator Index."""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    VerifySignaturesTestFiller,
    generate_pre_state,
)

from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_attestation_validator_index_out_of_range_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    An attestation whose participants include an index beyond the registry is rejected.

    Scenario
    --------
    - Anchor state has 4 validators.
    - Block at slot 2 carries one aggregated attestation whose participants
      bitfield includes validator index 99.
    - The attestation is marked valid_signature=False so the fixture path
      builds an invalid proof directly, without attempting XMSS signing for
      the out-of-range index.

    Expected Behavior
    -----------------
    Signature verification fails with AssertionError: "Validator index out of range"

    Why This Matters
    ----------------
    Enforces the validator-registry bound during attestation verification:

    - A malformed bitfield that references indices past the registry would
      otherwise cause undefined behaviour in public-key lookup.
    - The bound-check runs before attestation aggregate-signature verification
      so the failure reason is unambiguous across clients.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(),
        block=BlockSpec(
            slot=Slot(2),
            attestations=[
                AggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(99)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                    valid_signature=False,
                ),
            ],
        ),
        expect_exception=AssertionError,
    )
