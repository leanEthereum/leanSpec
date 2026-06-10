"""Single-message aggregate proof verification vectors — rejection cases."""

import pytest

from consensus_testing import (
    ExpectedRejection,
    IncrementEmittedSlot,
    RebindToAlternateHeadRoot,
    SwapParticipantPublicKey,
    VerifySingleMessageProofsTestFiller,
)
from lean_spec.spec.forks import Checkpoint, RejectionReason, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AttestationData
from lean_spec.spec.ssz import Bytes32

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


@pytest.mark.real_crypto(smoke=True)
def test_single_message_wrong_message(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """
    A proof rebound to an alternate head root is rejected.

    Given
    -----
    - one participating validator V0.
    - a proof rebound to a head root that differs from the honest message.

    When
    ----
    - the aggregate proof is verified.

    Then
    ----
    - verification fails because the signed message no longer matches the proof.
    """
    verify_single_message_proofs_test(
        validator_indices=[ValidatorIndex(0)],
        attestation_data=AttestationData(
            slot=Slot(6),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(6)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(6)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_SIGNATURE),
        tamper=RebindToAlternateHeadRoot(),
    )


def test_single_message_wrong_slot(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """
    A proof whose emitted slot is bumped past its bound slot is rejected.

    Given
    -----
    - one participating validator V0.
    - a proof bound to slot 4 but emitted under slot 5.

    When
    ----
    - the aggregate proof is verified.

    Then
    ----
    - verification fails because the emitted slot does not match the bound slot.
    """
    verify_single_message_proofs_test(
        validator_indices=[ValidatorIndex(0)],
        attestation_data=AttestationData(
            slot=Slot(4),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(4)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(4)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_SIGNATURE),
        tamper=IncrementEmittedSlot(),
    )


def test_single_message_wrong_public_keys(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """
    A proof whose participant key is swapped for another validator's is rejected.

    Given
    -----
    - one participating validator V0.
    - the public key at the only participant slot swapped for V1's key.

    When
    ----
    - the aggregate proof is verified.

    Then
    ----
    - verification fails because the proof was signed under a different key.
    """
    verify_single_message_proofs_test(
        validator_indices=[ValidatorIndex(0)],
        attestation_data=AttestationData(
            slot=Slot(7),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(7)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(7)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_SIGNATURE),
        tamper=SwapParticipantPublicKey(
            participant_index=0, with_validator_index=ValidatorIndex(1)
        ),
    )
