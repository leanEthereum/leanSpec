"""Type-1 multi-signature proof verification vectors — valid cases."""

import pytest
from consensus_testing import VerifyProofsTestFiller

from lean_spec.forks.lstar.containers import AttestationData
from lean_spec.types import Bytes32, Checkpoint, Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


HEAD_ROOT = Bytes32(b"\x11" * 32)
TARGET_ROOT = Bytes32(b"\x22" * 32)
SOURCE_ROOT = Bytes32(b"\x33" * 32)


def _make_attestation_data(slot: Slot) -> AttestationData:
    """Build an attestation data with deterministic roots for the given slot."""
    return AttestationData(
        slot=slot,
        head=Checkpoint(root=HEAD_ROOT, slot=slot),
        target=Checkpoint(root=TARGET_ROOT, slot=slot),
        source=Checkpoint(root=SOURCE_ROOT, slot=Slot(0)),
    )


def test_type_1_single_validator(
    verify_proofs_test: VerifyProofsTestFiller,
) -> None:
    """Single-validator Type-1 proof must verify.

    Smallest positive case for the multi-signature primitive.
    Catches clients that skip the degenerate one-participant branch
    or mis-bind the message and slot into the proof.
    """
    verify_proofs_test(
        validator_ids=[ValidatorIndex(0)],
        attestation_data=_make_attestation_data(Slot(1)),
        expect_valid=True,
    )


def test_type_1_four_validators(
    verify_proofs_test: VerifyProofsTestFiller,
) -> None:
    """Four-validator Type-1 proof, all participating, must verify.

    Matches existing unit-test scale.
    First vector with a contiguous all-participating bitfield.
    """
    verify_proofs_test(
        validator_ids=[ValidatorIndex(i) for i in range(4)],
        attestation_data=_make_attestation_data(Slot(2)),
        expect_valid=True,
    )


def test_type_1_four_validators_partial(
    verify_proofs_test: VerifyProofsTestFiller,
) -> None:
    """Four-validator committee with a non-contiguous participating set.

    Aggregation bits resolve to [1, 0, 1, 1].
    Catches clients that mis-index participants when the bitfield has
    a False slot interleaved with True ones.
    """
    verify_proofs_test(
        validator_ids=[ValidatorIndex(0), ValidatorIndex(2), ValidatorIndex(3)],
        attestation_data=_make_attestation_data(Slot(3)),
        expect_valid=True,
    )
