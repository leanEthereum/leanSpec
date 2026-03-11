from lean_spec.subspecs.containers.attestation import AttestationData, SignedAttestation
from lean_spec.subspecs.containers.block import (
    Block,
    BlockBody,
    BlockSignatures,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import Bytes32
from tests.lean_spec.helpers.builders import make_mock_signature


def test_encode_decode_signed_block_with_attestation_roundtrip() -> None:
    signed_block_with_attestation = SignedBlockWithAttestation(
        message=BlockWithAttestation(
            block=Block(
                slot=Slot(0),
                proposer_index=ValidatorIndex(0),
                parent_root=Bytes32.zero(),
                state_root=Bytes32.zero(),
                body=BlockBody(attestations=AggregatedAttestations(data=[])),
            ),
            proposer_attestation=SignedAttestation(
                validator_id=ValidatorIndex(0),
                data=AttestationData(
                    slot=Slot(0),
                    head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
                    target=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
                    source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
                ),
                signature=make_mock_signature(),
            ),
        ),
        signature=BlockSignatures(
            attestation_signatures=AttestationSignatures(data=[]),
            proposer_signature=make_mock_signature(),
        ),
    )

    encode = signed_block_with_attestation.encode_bytes()
    decoded = SignedBlockWithAttestation.decode_bytes(encode)
    assert decoded == signed_block_with_attestation
