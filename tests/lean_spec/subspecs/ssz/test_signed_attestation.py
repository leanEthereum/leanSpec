from lean_spec.forks.lstar.containers import AttestationData, Checkpoint, SignedAttestation
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex
from lean_spec.types import Bytes32
from tests.lean_spec.helpers.builders import make_mock_signature


def test_encode_decode_signed_attestation_roundtrip() -> None:
    attestation_data = AttestationData(
        slot=Slot(0),
        head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        target=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
    )
    signed_attestation = SignedAttestation(
        validator_id=ValidatorIndex(0),
        data=attestation_data,
        signature=make_mock_signature(),
    )

    encoded = signed_attestation.encode_bytes()
    decoded = SignedAttestation.decode_bytes(encoded)
    assert decoded == signed_attestation
