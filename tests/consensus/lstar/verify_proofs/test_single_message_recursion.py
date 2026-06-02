"""Single-message aggregate proof verification vectors — recursive aggregation cases."""

import pytest
from consensus_testing import (
    IncrementEmittedSlot,
    RebindToAlternateHeadRoot,
    VerifySingleMessageProofsTestFiller,
)

from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AggregationError, AttestationData
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def test_single_message_recursion_one_child_one_raw(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """Outer aggregate folding one single-validator child with one raw signer must verify."""
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
    """Outer aggregate folding two disjoint children with no raw signers must verify."""
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
    """Outer aggregate folding two children plus a raw signer must verify."""
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
    """Recursively folded proof rebound to an alternate head root must not verify."""
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
        expect_exception=AggregationError,
        tamper=RebindToAlternateHeadRoot(),
    )


def test_single_message_recursion_wrong_slot(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """Recursively folded proof bound to one slot but emitted under the next must not verify."""
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
        expect_exception=AggregationError,
        tamper=IncrementEmittedSlot(),
    )
