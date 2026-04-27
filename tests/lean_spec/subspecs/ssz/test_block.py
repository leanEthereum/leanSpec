from lean_spec.forks.lstar.containers.block import (
    Block,
    BlockBody,
    BlockSignatures,
    SignedBlock,
)
from lean_spec.forks.lstar.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex
from lean_spec.types import Bytes32
from tests.lean_spec.helpers.builders import make_mock_signature


def test_encode_decode_signed_block_roundtrip() -> None:
    block = Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    signed_block = SignedBlock(
        block=block,
        signature=BlockSignatures(
            attestation_signatures=AttestationSignatures(data=[]),
            proposer_signature=make_mock_signature(),
        ),
    )

    encode = signed_block.encode_bytes()
    decoded = SignedBlock.decode_bytes(encode)
    assert decoded == signed_block
