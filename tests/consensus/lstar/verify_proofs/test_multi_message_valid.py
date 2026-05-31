"""Multi-message aggregate proof verification vectors — valid cases."""

import pytest
from consensus_testing import VerifyMultiMessageProofsTestFiller

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


def test_multi_message_two_components_single_validator(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """Two components, each with one validator, must verify."""
    verify_multi_message_proofs_test(
        validator_indices_per_message=[
            [ValidatorIndex(0)],
            [ValidatorIndex(1)],
        ],
        attestation_data_per_message=[
            _make_attestation_data(Slot(10)),
            _make_attestation_data(Slot(11)),
        ],
    )


def test_multi_message_two_components_four_validators(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """Two components, each with a disjoint four-validator committee, must verify."""
    verify_multi_message_proofs_test(
        validator_indices_per_message=[
            [ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)],
            [ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)],
        ],
        attestation_data_per_message=[
            _make_attestation_data(Slot(12)),
            _make_attestation_data(Slot(13)),
        ],
    )


def test_multi_message_three_components_mixed_sizes(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """Three components with varying participant counts must verify."""
    verify_multi_message_proofs_test(
        validator_indices_per_message=[
            [ValidatorIndex(0), ValidatorIndex(2)],
            [ValidatorIndex(1), ValidatorIndex(3)],
            [ValidatorIndex(0)],
        ],
        attestation_data_per_message=[
            _make_attestation_data(Slot(14)),
            _make_attestation_data(Slot(15)),
            _make_attestation_data(Slot(16)),
        ],
    )
