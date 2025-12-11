from lean_spec.subspecs.containers.attestation import Attestation, AttestationData
from lean_spec.subspecs.containers.block import (
    Block,
    BlockBody,
    BlockSignatures,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestationList,
    AttestationSignatures,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss.constants import PROD_CONFIG
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.types import HashDigestList, HashTreeOpening, Randomness
from lean_spec.types import Bytes32, Uint64


def test_encode_decode_signed_block_with_attestation_roundtrip() -> None:
    signed_block_with_attestation = SignedBlockWithAttestation(
        message=BlockWithAttestation(
            block=Block(
                slot=0,
                proposer_index=Uint64(0),
                parent_root=Bytes32.zero(),
                state_root=Bytes32.zero(),
                body=BlockBody(attestations=AggregatedAttestationList(data=[])),
            ),
            proposer_attestation=Attestation(
                validator_id=Uint64(0),
                data=AttestationData(
                    slot=0,
                    head=Checkpoint(root=Bytes32.zero(), slot=0),
                    target=Checkpoint(root=Bytes32.zero(), slot=0),
                    source=Checkpoint(root=Bytes32.zero(), slot=0),
                ),
            ),
        ),
        signature=BlockSignatures(
            attestation_signatures=AttestationSignatures(data=[]),
            proposer_signature=Signature(
                path=HashTreeOpening(siblings=HashDigestList(data=[])),
                rho=Randomness(data=[Fp(0) for _ in range(PROD_CONFIG.RAND_LEN_FE)]),
                hashes=HashDigestList(data=[]),
            ),
        ),
    )

    encode = signed_block_with_attestation.encode_bytes()
    expected_value = (
        "08000000ec0000008c00000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000054000000040000000800000008000000240000000"
        "00000000000000000000000000000000000000000000000000000002800000004000000"
    )
    assert encode.hex() == expected_value, "Encoded value must match hardcoded expected value"
    assert SignedBlockWithAttestation.decode_bytes(encode) == signed_block_with_attestation
