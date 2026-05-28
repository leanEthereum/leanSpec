"""Signature verification: structural rejection vectors for the merged proof.

These cover structural invariants a peer could break that the block
builder upholds by construction:

- the merged proof must decode,
- its component count must match the body plus the proposer,
- each component stays bound to the message it signed.
"""

import pytest
from consensus_testing import (
    BlockSpec,
    VerifySignaturesTestFiller,
    generate_pre_state,
)

from lean_spec.spec.forks import Slot

pytestmark = pytest.mark.valid_until("Lstar")


def test_corrupt_proof_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """A signed block whose merged proof does not decode is rejected.

    Scenario
    --------
    - Anchor state has 1 validator.
    - Block at slot 1 carries only the proposer component.
    - The tamper hook overwrites the merged proof with a short blob.

    Expected Behavior
    -----------------
    Verification fails with AssertionError because the Type-2 envelope
    cannot be decoded.

    Why This Matters
    ----------------
    The proof blob arrives over the wire.
    A peer can send arbitrary bytes.
    Clients must reject before attempting to verify a malformed proof.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=1),
        block=BlockSpec(slot=Slot(1), attestations=[]),
        tamper={"operation": "corrupt_proof"},
        expect_exception=AssertionError,
    )


def test_proof_component_count_mismatch_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """A block whose body claims more components than the proof is rejected.

    Scenario
    --------
    - Anchor state has 1 validator.
    - Block at slot 1 carries only the proposer component.
    - The tamper hook appends a body attestation that has no matching
      proof component.

    Expected Behavior
    -----------------
    Verification fails with AssertionError: the proof component count no
    longer matches the body plus the proposer.

    Why This Matters
    ----------------
    The merged proof and the body attestation list are parallel.
    A peer could add body entries to credit votes the proof never
    carried.
    Clients must reject any count mismatch.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=1),
        block=BlockSpec(slot=Slot(1), attestations=[]),
        tamper={"operation": "append_phantom_attestation"},
        expect_exception=AssertionError,
    )


def test_proof_reused_under_different_message_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """An honest proof reused under a different block is rejected.

    Scenario
    --------
    - Anchor state has 1 validator.
    - Block at slot 1 is signed honestly.
    - The tamper hook rewrites the block's state root after signing, so
      the block root differs while the proof is unchanged.

    Expected Behavior
    -----------------
    Verification fails with AssertionError: each proof component is bound
    to the message it signed, and the proposer component no longer
    matches the recomputed block root.

    Why This Matters
    ----------------
    Without the per-component binding, honest signatures could be lifted
    onto attacker-chosen block or attestation data that resolves to the
    same public keys.
    Validators would be credited for messages they never signed, directly
    attackable for justification manipulation.
    This pins the binding that closes that hole.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=1),
        block=BlockSpec(slot=Slot(1), attestations=[]),
        tamper={"operation": "mutate_state_root"},
        expect_exception=AssertionError,
    )
