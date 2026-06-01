"""Multi-message aggregate proof verification vectors — valid cases."""

import pytest
from consensus_testing import VerifyMultiMessageProofsTestFiller

from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AttestationData
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def test_multi_message_single_component_single_validator(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """A single-component bundle with one validator must verify."""
    verify_multi_message_proofs_test(
        validator_indices_per_message=[
            [ValidatorIndex(0)],
        ],
        attestation_data_per_message=[
            AttestationData(
                slot=Slot(1),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(1)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(1)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
        ],
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
            AttestationData(
                slot=Slot(10),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(10)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(10)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
            AttestationData(
                slot=Slot(11),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(11)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(11)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
        ],
    )


def test_multi_message_two_components_four_validators(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """Two components, each with a full four-validator committee, must verify."""
    verify_multi_message_proofs_test(
        validator_indices_per_message=[
            [ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)],
            [ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)],
        ],
        attestation_data_per_message=[
            AttestationData(
                slot=Slot(12),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(12)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(12)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
            AttestationData(
                slot=Slot(13),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(13)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(13)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
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
            AttestationData(
                slot=Slot(14),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(14)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(14)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
            AttestationData(
                slot=Slot(15),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(15)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(15)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
            AttestationData(
                slot=Slot(16),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(16)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(16)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
        ],
    )


def test_multi_message_component_partial_participation(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """A non-contiguous committee whose aggregation bits resolve to [1, 0, 1, 1] must verify."""
    verify_multi_message_proofs_test(
        validator_indices_per_message=[
            [ValidatorIndex(0), ValidatorIndex(2), ValidatorIndex(3)],
            [ValidatorIndex(1)],
        ],
        attestation_data_per_message=[
            AttestationData(
                slot=Slot(17),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(17)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(17)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
            AttestationData(
                slot=Slot(18),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(18)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(18)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
        ],
    )
