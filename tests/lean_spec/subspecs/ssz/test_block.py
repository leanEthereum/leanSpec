from lean_spec.subspecs.containers.attestation import (
    Attestation,
    AttestationData,
)
from lean_spec.subspecs.containers.block.block import (
    Block,
    BlockBody,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import Attestations, BlockSignatures
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.types import Bytes32, ValidatorIndex


def test_encode_decode_signed_block_with_attestation_roundtrip() -> None:
    signed_block_with_attestation = SignedBlockWithAttestation(
        message=BlockWithAttestation(
            block=Block(
                slot=0,
                proposer_index=ValidatorIndex(0),
                parent_root=Bytes32.zero(),
                state_root=Bytes32.zero(),
                body=BlockBody(attestations=Attestations(data=[])),
            ),
            proposer_attestation=Attestation(
                validator_id=ValidatorIndex(0),
                data=AttestationData(
                    slot=0,
                    head=Checkpoint(root=Bytes32.zero(), slot=0),
                    target=Checkpoint(root=Bytes32.zero(), slot=0),
                    source=Checkpoint(root=Bytes32.zero(), slot=0),
                ),
            ),
        ),
        signature=BlockSignatures(data=[]),
    )

    encode = signed_block_with_attestation.encode_bytes()
    expected_value = (
        "08000000ec0000008c000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000005400000004000000"
    )
    assert encode.hex() == expected_value
    assert SignedBlockWithAttestation.decode_bytes(encode) == signed_block_with_attestation
