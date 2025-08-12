"""
Tests for the client's Vote container.
"""

from ethereum_types.bytes import Bytes32
from ethereum_types.numeric import U64

from lean_spec.client.checkpoint import Checkpoint
from lean_spec.client.vote import Vote


def test_vote():
    Vote(
        validator_id=U64(1),
        slot=U64(2),
        head=Checkpoint(
            root=Bytes32(b"\x03" * 32),
            slot=U64(3),
        ),
        source=Checkpoint(
            root=Bytes32(b"\x05" * 32),
            slot=U64(5),
        ),
        target=Checkpoint(
            root=Bytes32(b"\x04" * 32),
            slot=U64(4),
        ),
    )
