"""Single-message aggregate proof verification vectors — rejection cases."""

import pytest
from consensus_testing import (
    IncrementEmittedSlot,
    RebindToAlternateHeadRoot,
    SwapParticipantPublicKey,
    VerifyProofsTestFiller,
)

from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AggregationError, AttestationData
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def test_single_message_wrong_message(
    verify_proofs_test: VerifyProofsTestFiller,
) -> None:
    """Proof bound to an alternate head root must not verify against the honest message."""
    verify_proofs_test(
        validator_indices=[ValidatorIndex(0)],
        attestation_data=AttestationData(
            slot=Slot(6),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(6)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(6)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
        expect_exception=AggregationError,
        tamper=RebindToAlternateHeadRoot(),
    )


def test_single_message_wrong_slot(
    verify_proofs_test: VerifyProofsTestFiller,
) -> None:
    """Proof bound to slot 4, emitted under slot 5, must reject on the slot binding mismatch."""
    verify_proofs_test(
        validator_indices=[ValidatorIndex(0)],
        attestation_data=AttestationData(
            slot=Slot(4),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(4)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(4)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
        expect_exception=AggregationError,
        tamper=IncrementEmittedSlot(),
    )


def test_single_message_wrong_public_keys(
    verify_proofs_test: VerifyProofsTestFiller,
) -> None:
    """Public key at the only participant slot swapped for another validator's must reject."""
    verify_proofs_test(
        validator_indices=[ValidatorIndex(0)],
        attestation_data=AttestationData(
            slot=Slot(7),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(7)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(7)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
        expect_exception=AggregationError,
        tamper=SwapParticipantPublicKey(index=0, with_validator_index=ValidatorIndex(1)),
    )
