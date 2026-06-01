"""Multi-message aggregate proof verification vectors — rejection cases."""

import pytest
from consensus_testing import (
    DropComponentMessageBinding,
    IncrementComponentSlot,
    RebindComponentToAlternateHeadRoot,
    SwapComponentMessageBindings,
    SwapComponentParticipantPublicKey,
    VerifyMultiMessageProofsTestFiller,
)

from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AggregationError, AttestationData
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


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
            AttestationData(
                slot=Slot(19),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(19)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(19)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
            AttestationData(
                slot=Slot(20),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(20)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(20)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
        ],
        expect_exception=AggregationError,
        tamper=IncrementComponentSlot(component_index=1),
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
            AttestationData(
                slot=Slot(22),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(22)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(22)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
            AttestationData(
                slot=Slot(23),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(23)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(23)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
        ],
        expect_exception=AggregationError,
        tamper=SwapComponentParticipantPublicKey(
            component_index=1,
            participant_index=0,
            with_validator_index=ValidatorIndex(2),
        ),
    )


def test_multi_message_components_with_swapped_bindings(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """Two components whose message-slot bindings are transposed must fail multi-message verify."""
    verify_multi_message_proofs_test(
        validator_indices_per_message=[
            [ValidatorIndex(0)],
            [ValidatorIndex(1)],
        ],
        attestation_data_per_message=[
            AttestationData(
                slot=Slot(24),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(24)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(24)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
            AttestationData(
                slot=Slot(25),
                head=Checkpoint(root=Bytes32(b"\x44" * 32), slot=Slot(25)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(25)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
        ],
        expect_exception=AggregationError,
        tamper=SwapComponentMessageBindings(
            first_component_index=0,
            second_component_index=1,
        ),
    )


def test_multi_message_missing_one_component_binding(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """A binding list shorter than the key list must fail multi-message verify."""
    verify_multi_message_proofs_test(
        validator_indices_per_message=[
            [ValidatorIndex(0)],
            [ValidatorIndex(1)],
        ],
        attestation_data_per_message=[
            AttestationData(
                slot=Slot(26),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(26)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(26)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
            AttestationData(
                slot=Slot(27),
                head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(27)),
                target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(27)),
                source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
            ),
        ],
        expect_exception=AggregationError,
        tamper=DropComponentMessageBinding(component_index=1),
    )
