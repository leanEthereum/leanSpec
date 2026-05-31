"""Multi-message aggregate proof verification vectors — rejection cases."""

import pytest
from consensus_testing import (
    IncrementComponentSlot,
    RebindComponentToAlternateHeadRoot,
    SwapComponentParticipantPublicKey,
    VerifyMultiMessageProofsTestFiller,
)

from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AggregationError, AttestationData
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def _make_attestation_data(slot: Slot) -> AttestationData:
    return AttestationData(
        slot=slot,
        head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=slot),
        target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=slot),
        source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
    )


def test_multi_message_wrong_message_in_one_component(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """One component rebound to an alternate head root must fail multi-message verify."""
    verify_multi_message_proofs_test(
        validator_indices_per_message=[
            [ValidatorIndex(0)],
            [ValidatorIndex(1)],
        ],
        attestation_data_per_message=[
            _make_attestation_data(Slot(17)),
            _make_attestation_data(Slot(18)),
        ],
        expect_exception=AggregationError,
        tamper=RebindComponentToAlternateHeadRoot(component_index=1),
    )


def test_multi_message_wrong_slot_in_one_component(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """One component's emitted slot bumped past its bound slot must fail multi-message verify."""
    verify_multi_message_proofs_test(
        validator_indices_per_message=[
            [ValidatorIndex(0)],
            [ValidatorIndex(1)],
        ],
        attestation_data_per_message=[
            _make_attestation_data(Slot(19)),
            _make_attestation_data(Slot(21)),
        ],
        expect_exception=AggregationError,
        tamper=IncrementComponentSlot(component_index=0),
    )


def test_multi_message_wrong_public_key_in_one_component(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """One participant's key swapped for another validator's must fail multi-message verify."""
    verify_multi_message_proofs_test(
        validator_indices_per_message=[
            [ValidatorIndex(0)],
            [ValidatorIndex(1)],
        ],
        attestation_data_per_message=[
            _make_attestation_data(Slot(22)),
            _make_attestation_data(Slot(23)),
        ],
        expect_exception=AggregationError,
        tamper=SwapComponentParticipantPublicKey(
            component_index=1,
            index=0,
            with_validator_index=ValidatorIndex(2),
        ),
    )
