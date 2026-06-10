"""Signature verification rejects merged proofs that break structural invariants."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    AppendPhantomAttestation,
    BlockSpec,
    CorruptProof,
    ExpectedRejection,
    MutateStateRoot,
    SwapFirstTwoAttestations,
    VerifySignaturesTestFiller,
    build_anchor,
    generate_pre_state,
)
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


@pytest.mark.real_crypto(smoke=True)
def test_corrupt_proof_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A block whose merged proof does not decode is rejected.

    Given
    -----
    - a registry of 1 validator.
    - a block at slot 1 carrying only the proposer component.
    - the merged proof is overwritten with a short blob.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification is rejected as an invalid block proof.
    - the aggregate envelope cannot be decoded.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=1),
        block=BlockSpec(slot=Slot(1), attestations=[]),
        tamper=CorruptProof(),
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_BLOCK_PROOF),
    )


def test_proof_component_count_mismatch_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A block whose body claims more components than the proof carries is rejected.

    Given
    -----
    - a registry of 1 validator.
    - a block at slot 1 carrying only the proposer component.
    - a body attestation is appended that has no matching proof component.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification is rejected as an invalid block proof.
    - the proof component count no longer matches the body plus the proposer.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=1),
        block=BlockSpec(slot=Slot(1), attestations=[]),
        tamper=AppendPhantomAttestation(),
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_BLOCK_PROOF),
    )


@pytest.mark.real_crypto(smoke=True)
def test_proof_reused_under_different_message_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    An honest proof reused under a different block is rejected.

    Given
    -----
    - a registry of 1 validator.
    - a block at slot 1 signed honestly.
    - the block state root is rewritten after signing, so the block root differs.
    - the proof is left unchanged.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification is rejected as an invalid block proof.
    - the proposer component no longer matches the recomputed block root.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=1),
        block=BlockSpec(slot=Slot(1), attestations=[]),
        tamper=MutateStateRoot(),
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_BLOCK_PROOF),
    )


def test_attestation_proof_order_mismatch_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A block whose body order no longer matches proof order is rejected.

    Given
    -----
    - a registry of 4 validators.
    - a block at slot 3 carrying an aggregate from V0 then an aggregate from V2.
    - the two body attestations are swapped after signing.
    - the proof order is left unchanged.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification is rejected as an invalid block proof.
    - each proof component no longer aligns with its body attestation.
    """
    anchor_state, anchor_block = build_anchor(num_validators=4, anchor_slot=Slot(2))
    parent_root = hash_tree_root(anchor_block)

    verify_signatures_test(
        anchor_state=anchor_state,
        block=BlockSpec(
            slot=Slot(3),
            parent_root=parent_root,
            attestations=[
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0)],
                    slot=Slot(3),
                    target_slot=Slot(1),
                    target_root=anchor_state.historical_block_hashes[1],
                    head_root=parent_root,
                    head_slot=Slot(2),
                ),
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(2)],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root=parent_root,
                    head_root=parent_root,
                    head_slot=Slot(2),
                ),
            ],
        ),
        tamper=SwapFirstTwoAttestations(),
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_BLOCK_PROOF),
    )
