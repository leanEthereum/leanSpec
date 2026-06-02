"""Single-message aggregate proof verification vectors — recursive aggregation cases."""

import pytest
from consensus_testing import VerifySingleMessageProofsTestFiller

from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AttestationData
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def _make_attestation_data(slot: Slot) -> AttestationData:
    return AttestationData(
        slot=slot,
        head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=slot),
        target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=slot),
        source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
    )


def test_single_message_recursion_one_child_one_raw(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """Outer aggregate folding one single-validator child with one raw signer must verify."""
    verify_single_message_proofs_test(
        validator_indices=[ValidatorIndex(0), ValidatorIndex(1)],
        attestation_data=_make_attestation_data(Slot(25)),
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
        attestation_data=_make_attestation_data(Slot(26)),
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
        attestation_data=_make_attestation_data(Slot(27)),
        child_groups=[
            [ValidatorIndex(0), ValidatorIndex(1)],
            [ValidatorIndex(2)],
        ],
    )
