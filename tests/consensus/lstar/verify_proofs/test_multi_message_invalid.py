"""Multi-message aggregate proof verification vectors — rejection cases."""

import pytest

from consensus_testing import (
    DropMessageBinding,
    ExpectedRejection,
    IncrementEmittedSlot,
    RebindToAlternateHeadRoot,
    SwapMessageBindings,
    SwapParticipantPublicKey,
    VerifyMultiMessageProofsTestFiller,
)
from lean_spec.spec.forks import Checkpoint, RejectionReason, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AttestationData
from lean_spec.spec.ssz import Bytes32

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


def test_multi_message_wrong_message_in_one_component(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """
    A bundle where one component is rebound to an alternate head root is rejected.

    Given
    -----
    - one component with participating validator V0.
    - one component with participating validator V1.
    - the second component rebound to a head root that differs from its honest message.

    When
    ----
    - the multi-message bundle is verified.

    Then
    ----
    - verification fails because one component's signed message no longer matches its proof.
    """
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
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_SIGNATURE),
        tamper=RebindToAlternateHeadRoot(component_index=1),
    )


def test_multi_message_wrong_slot_in_one_component(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """
    A bundle where one component's emitted slot is bumped past its bound slot is rejected.

    Given
    -----
    - one component with participating validator V0.
    - one component with participating validator V1.
    - the second component's emitted slot bumped past its bound slot.

    When
    ----
    - the multi-message bundle is verified.

    Then
    ----
    - verification fails because one component's emitted slot does not match its bound slot.
    """
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
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_SIGNATURE),
        tamper=IncrementEmittedSlot(component_index=1),
    )


def test_multi_message_wrong_public_key_in_one_component(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """
    A bundle where one participant's key is swapped for another validator's is rejected.

    Given
    -----
    - one component with participating validator V0.
    - one component with participating validator V1.
    - the second component's only participant key swapped for V2's key.

    When
    ----
    - the multi-message bundle is verified.

    Then
    ----
    - verification fails because one component was signed under a different key.
    """
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
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_SIGNATURE),
        tamper=SwapParticipantPublicKey(
            component_index=1,
            participant_index=0,
            with_validator_index=ValidatorIndex(2),
        ),
    )


def test_multi_message_components_with_swapped_bindings(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """
    A bundle whose two component message bindings are transposed is rejected.

    Given
    -----
    - one component with participating validator V0.
    - one component with participating validator V1.
    - the message bindings of the two components transposed.

    When
    ----
    - the multi-message bundle is verified.

    Then
    ----
    - verification fails because each component is checked against the wrong message.
    """
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
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_SIGNATURE),
        tamper=SwapMessageBindings(
            first_component_index=0,
            second_component_index=1,
        ),
    )


def test_multi_message_missing_one_component_binding(
    verify_multi_message_proofs_test: VerifyMultiMessageProofsTestFiller,
) -> None:
    """
    A bundle with one component binding dropped is rejected.

    Given
    -----
    - one component with participating validator V0.
    - one component with participating validator V1.
    - the second component's message binding dropped.
    - the binding list now shorter than the key list.

    When
    ----
    - the multi-message bundle is verified.

    Then
    ----
    - verification fails because a key has no message binding to check against.
    """
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
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_SIGNATURE),
        tamper=DropMessageBinding(component_index=1),
    )
