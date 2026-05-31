"""Single-message aggregate proof verification vectors — valid cases."""

import pytest
from consensus_testing import VerifySingleMessageProofsTestFiller

from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AttestationData
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def test_single_message_single_validator(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """Single-validator single-message aggregate proof must verify."""
    verify_single_message_proofs_test(
        validator_indices=[ValidatorIndex(0)],
        attestation_data=AttestationData(
            slot=Slot(1),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(1)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(1)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
    )


def test_single_message_four_validators(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """Four-validator single-message aggregate, all participating, must verify."""
    verify_single_message_proofs_test(
        validator_indices=[ValidatorIndex(i) for i in range(4)],
        attestation_data=AttestationData(
            slot=Slot(2),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(2)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(2)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
    )


def test_single_message_four_validators_partial(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """Non-contiguous four-validator committee, aggregation bits resolve to [1, 0, 1, 1]."""
    verify_single_message_proofs_test(
        validator_indices=[ValidatorIndex(0), ValidatorIndex(2), ValidatorIndex(3)],
        attestation_data=AttestationData(
            slot=Slot(3),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(3)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(3)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
    )
