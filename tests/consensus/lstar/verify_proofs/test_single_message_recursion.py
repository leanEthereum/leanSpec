"""Single-message aggregate proof verification vectors — recursive aggregation cases."""

import pytest

from consensus_testing import (
    ExpectedRejection,
    IncrementEmittedSlot,
    RebindToAlternateHeadRoot,
    VerifySingleMessageProofsTestFiller,
)
from lean_spec.spec.forks import Checkpoint, RejectionReason, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AttestationData
from lean_spec.spec.ssz import Bytes32

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


def test_single_message_recursion_one_child_one_raw(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """
    An outer aggregate folding one child and one raw signer verifies.

    Given
    -----
    - an outer aggregate over V0 and V1.
    - one child aggregate covering V0.
    - V1 contributing as a raw signer.

    When
    ----
    - the aggregate proof is verified.

    Then
    ----
    - verification succeeds.
    """
    verify_single_message_proofs_test(
        validator_indices=[ValidatorIndex(0), ValidatorIndex(1)],
        attestation_data=AttestationData(
            slot=Slot(25),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(25)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(25)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
        child_groups=[[ValidatorIndex(0)]],
    )


def test_single_message_recursion_two_children(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """
    An outer aggregate folding two disjoint children with no raw signers verifies.

    Given
    -----
    - an outer aggregate over V0 through V3.
    - one child aggregate covering V0 and V1.
    - one child aggregate covering V2 and V3.

    When
    ----
    - the aggregate proof is verified.

    Then
    ----
    - verification succeeds.
    """
    verify_single_message_proofs_test(
        validator_indices=[
            ValidatorIndex(0),
            ValidatorIndex(1),
            ValidatorIndex(2),
            ValidatorIndex(3),
        ],
        attestation_data=AttestationData(
            slot=Slot(26),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(26)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(26)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
        child_groups=[
            [ValidatorIndex(0), ValidatorIndex(1)],
            [ValidatorIndex(2), ValidatorIndex(3)],
        ],
    )


def test_single_message_recursion_two_children_with_raw(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """
    An outer aggregate folding two children plus a raw signer verifies.

    Given
    -----
    - an outer aggregate over V0 through V3.
    - one child aggregate covering V0 and V1.
    - one child aggregate covering V2.
    - V3 contributing as a raw signer.

    When
    ----
    - the aggregate proof is verified.

    Then
    ----
    - verification succeeds.
    """
    verify_single_message_proofs_test(
        validator_indices=[
            ValidatorIndex(0),
            ValidatorIndex(1),
            ValidatorIndex(2),
            ValidatorIndex(3),
        ],
        attestation_data=AttestationData(
            slot=Slot(27),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(27)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(27)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
        child_groups=[
            [ValidatorIndex(0), ValidatorIndex(1)],
            [ValidatorIndex(2)],
        ],
    )


def test_single_message_recursion_wrong_message(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """
    A recursively folded proof rebound to an alternate head root is rejected.

    Given
    -----
    - an outer aggregate over V0 through V3.
    - one child aggregate covering V0 and V1.
    - one child aggregate covering V2 and V3.
    - the proof rebound to a head root that differs from the honest message.

    When
    ----
    - the aggregate proof is verified.

    Then
    ----
    - verification fails because the signed message no longer matches the proof.
    """
    verify_single_message_proofs_test(
        validator_indices=[
            ValidatorIndex(0),
            ValidatorIndex(1),
            ValidatorIndex(2),
            ValidatorIndex(3),
        ],
        attestation_data=AttestationData(
            slot=Slot(28),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(28)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(28)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
        child_groups=[
            [ValidatorIndex(0), ValidatorIndex(1)],
            [ValidatorIndex(2), ValidatorIndex(3)],
        ],
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_SIGNATURE),
        tamper=RebindToAlternateHeadRoot(),
    )


def test_single_message_recursion_wrong_slot(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """
    A recursively folded proof emitted under the wrong slot is rejected.

    Given
    -----
    - an outer aggregate over V0 through V3.
    - one child aggregate covering V0 and V1.
    - one child aggregate covering V2.
    - the proof bound to one slot but emitted under the next.

    When
    ----
    - the aggregate proof is verified.

    Then
    ----
    - verification fails because the emitted slot does not match the bound slot.
    """
    verify_single_message_proofs_test(
        validator_indices=[
            ValidatorIndex(0),
            ValidatorIndex(1),
            ValidatorIndex(2),
            ValidatorIndex(3),
        ],
        attestation_data=AttestationData(
            slot=Slot(29),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(29)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(29)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
        child_groups=[
            [ValidatorIndex(0), ValidatorIndex(1)],
            [ValidatorIndex(2)],
        ],
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_SIGNATURE),
        tamper=IncrementEmittedSlot(),
    )
