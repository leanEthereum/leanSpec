from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Checkpoint,
    Signature,
    SignedAttestation,
)
from lean_spec.subspecs.containers.block.types import BlockSignatures
from lean_spec.types.byte_arrays import Bytes32
from lean_spec.types.validator import ValidatorIndex


def test_encode_decode_signed_attestation_roundtrip() -> None:
    signed_attestation = SignedAttestation(
        message=Attestation(
            validator_id=ValidatorIndex(0),
            data=AttestationData(
                slot=0,
                head=Checkpoint(root=Bytes32.zero(), slot=0),
                target=Checkpoint(root=Bytes32.zero(), slot=0),
                source=Checkpoint(root=Bytes32.zero(), slot=0),
            ),
        ),
        signature=Signature.zero(),
    )

    encode = signed_attestation.encode_bytes()
    expected_value = "0" * 6504
    assert encode.hex() == expected_value
    assert SignedAttestation.decode_bytes(encode) == signed_attestation
