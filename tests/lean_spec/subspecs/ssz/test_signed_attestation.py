from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Checkpoint,
    SignedAttestation,
)
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss.constants import PROD_CONFIG
from lean_spec.subspecs.xmss.containers import (
    HashDigestList,
    HashTreeOpening,
    Randomness,
    Signature,
)
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
        signature=Signature(
            path=HashTreeOpening(siblings=HashDigestList(data=[])),
            rho=Randomness(data=[Fp(0) for _ in range(PROD_CONFIG.RAND_LEN_FE)]),
            hashes=HashDigestList(data=[]),
        ),
    )

    # Test that encoding and decoding round-trips correctly
    encode = signed_attestation.encode_bytes()
    decoded = SignedAttestation.decode_bytes(encode)
    assert decoded == signed_attestation
