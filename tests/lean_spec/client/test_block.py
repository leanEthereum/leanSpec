"""
Tests for the client's Block container.
"""

from ethereum_types.bytes import Bytes32
from ethereum_types.numeric import U64
from ssz.sedes.list import List

from lean_spec.client.block import Block
from lean_spec.client.checkpoint import Checkpoint
from lean_spec.client.preset import VALIDATOR_REGISTRY_LIMIT
from lean_spec.client.vote import Vote


def test_block():

    Block(
        slot=U64(1),
        parent=Bytes32(b"\x02" * 32),
        votes=List(
            Vote(
                validator_id=U64(1),
                slot=U64(2),
                head=Checkpoint(
                    root=Bytes32(b"\x04" * 32),
                    slot=U64(3),
                ),
                source=Checkpoint(
                    root=Bytes32(b"\x05" * 32),
                    slot=U64(5),
                ),
                target=Checkpoint(
                    root=Bytes32(b"\x06" * 32),
                    slot=U64(4),
                ),
            ),
            int(VALIDATOR_REGISTRY_LIMIT),
        ),
        state_root=Bytes32(b"\x03" * 32),
    )
