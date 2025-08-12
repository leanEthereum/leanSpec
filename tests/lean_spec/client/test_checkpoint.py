"""
Tests for the client's Checkpoint container.
"""

from ethereum_types.bytes import Bytes32
from ethereum_types.numeric import U64

from lean_spec.client.checkpoint import Checkpoint


def test_checkpoint():

    Checkpoint(
        root=Bytes32(b"\x42" * 32),
        slot=U64(42),
    )

