"""Single-message aggregate proof verification vectors — valid cases."""

import pytest

from consensus_testing import VerifySingleMessageProofsTestFiller
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AttestationData
from lean_spec.spec.ssz import Bytes32

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


@pytest.mark.real_crypto(smoke=True)
def test_single_message_single_validator(
    verify_single_message_proofs_test: VerifySingleMessageProofsTestFiller,
) -> None:
    """
    A single-validator aggregate proof over one message verifies.

    Given
    -----
    - one participating validator V0.
    - a single attestation message.

    When
    ----
    - the aggregate proof is verified.

    Then
    ----
    - verification succeeds.
    """
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
    """
    A four-validator aggregate over one message verifies when all participate.

    Given
    -----
    - four validators V0 through V3, all participating.
    - a single attestation message.

    When
    ----
    - the aggregate proof is verified.

    Then
    ----
    - verification succeeds.
    """
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
    """
    A non-contiguous committee verifies when only some validators participate.

    Given
    -----
    - a four-validator committee where V0, V2, and V3 participate.
    - aggregation bits resolving to [1, 0, 1, 1].
    - a single attestation message.

    When
    ----
    - the aggregate proof is verified.

    Then
    ----
    - verification succeeds.
    """
    verify_single_message_proofs_test(
        validator_indices=[ValidatorIndex(0), ValidatorIndex(2), ValidatorIndex(3)],
        attestation_data=AttestationData(
            slot=Slot(3),
            head=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(3)),
            target=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(3)),
            source=Checkpoint(root=Bytes32(b"\x33" * 32), slot=Slot(0)),
        ),
    )
