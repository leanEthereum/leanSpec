from lean_spec.forks.lstar.containers.block import Block, BlockBody, SignedBlock
from lean_spec.forks.lstar.containers.block.types import AggregatedAttestations
from lean_spec.types import ByteList512KiB, Bytes32, Slot, ValidatorIndex


def test_encode_decode_signed_block_roundtrip() -> None:
    block = Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    signed_block = SignedBlock(block=block, proof=ByteList512KiB(data=b""))

    encode = signed_block.encode_bytes()
    decoded = SignedBlock.decode_bytes(encode)
    assert decoded == signed_block
