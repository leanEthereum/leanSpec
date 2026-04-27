"""Signature verification: structural-invariant rejection vectors.

Exercises rejection paths that lie behind structural invariants the
block builder normally upholds. The verify_signatures fixture's tamper
hook mutates a validly built signed block so the rejection path fires
on verify.
"""

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


def test_signature_group_count_mismatch_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """A signed block with fewer signature groups than attestations is rejected.

    Scenario
    --------
    - Anchor state has 4 validators.
    - Block at slot 2 carries one aggregated attestation.
    - After the block is built, the tamper hook drops the last signature
      group, leaving one attestation and zero signature groups.

    Expected Behavior
    -----------------
    Signature verification fails with AssertionError:
    "Attestation signature groups must align with block body attestations"

    Why This Matters
    ----------------
    Pins a structural check the block builder enforces by construction:

    - Each aggregated attestation must have a corresponding signature.
    - A peer could send a malformed signed block with missing signature
      groups; the receiving client must reject it before verifying any
      individual signature.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=3),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(0)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                    valid_signature=False,
                ),
            ],
        ),
        tamper={"operation": "drop_last_signature"},
        expect_exception=AssertionError,
    )
