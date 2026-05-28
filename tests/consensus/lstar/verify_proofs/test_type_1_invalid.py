"""Type-1 multi-signature proof verification vectors — rejection cases."""

import pytest
from consensus_testing import VerifyProofsTestFiller

from lean_spec.forks.lstar.containers import AttestationData
from lean_spec.subspecs.xmss.aggregation import AggregationError
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


def test_type_1_wrong_message(
    verify_proofs_test: VerifyProofsTestFiller,
) -> None:
    """Proof bound to a different message must not verify.

    The emitted attestation data is honest, but the proof bytes were
    produced by signing an alternate attestation data with a different
    head root.
    A client recomputes the emitted attestation root, matches the
    emitted message field, then verifies the proof against that
    message and must reject.
    """
    verify_proofs_test(
        validator_ids=[ValidatorIndex(0)],
        attestation_data=_make_attestation_data(Slot(6)),
        expect_exception=AggregationError,
        tamper={"operation": "rebind_with_alt_head_root"},
    )


def test_type_1_wrong_slot(
    verify_proofs_test: VerifyProofsTestFiller,
) -> None:
    """Proof bound to one slot, emitted under a different slot, must reject.

    The proof was honestly generated at slot 4, but the emitted slot
    field is bumped to 5.
    A client must verify the proof against the emitted slot field and
    reject on the slot binding mismatch.
    A client that derives the verifier slot from any other source
    would incorrectly accept the vector.
    """
    verify_proofs_test(
        validator_ids=[ValidatorIndex(0)],
        attestation_data=_make_attestation_data(Slot(4)),
        expect_exception=AggregationError,
        tamper={"operation": "shift_emitted_slot"},
    )


def test_type_1_wrong_public_keys(
    verify_proofs_test: VerifyProofsTestFiller,
) -> None:
    """Swapped public key at one participant slot must cause rejection.

    The proof was generated using validator 0's attestation key, but
    the emitted public key set carries validator 1's key in its place.
    """
    verify_proofs_test(
        validator_ids=[ValidatorIndex(0)],
        attestation_data=_make_attestation_data(Slot(7)),
        expect_exception=AggregationError,
        tamper={"operation": "swap_public_key", "index": 0, "with_validator_id": 1},
    )
