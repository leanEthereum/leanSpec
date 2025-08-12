"""
Tests for the client's State container.
"""

from ethereum_types.bytes import Bytes32
from ethereum_types.numeric import U64
from ssz.sedes.bitlist import Bitlist
from ssz.sedes.list import List

from lean_spec.client.checkpoint import Checkpoint
from lean_spec.client.preset import (
    MAX_HISTORICAL_BLOCK_HASHES,
    VALIDATOR_REGISTRY_LIMIT,
)
from lean_spec.client.state import State


def test_state():
    State(
        latest_justified=Checkpoint(
            root=Bytes32(b"\x00" * 32),
            slot=U64(0),
        ),
        latest_finalized=Checkpoint(
            root=Bytes32(b"\x00" * 32),
            slot=U64(0),
        ),
        historical_block_hashes=List(
            [
                Bytes32(b"\x00" * 32),
                Bytes32(b"\x01" * 32),
            ],
            int(MAX_HISTORICAL_BLOCK_HASHES),
        ),
        justified_slots=List(
            [
                True,
                False,
            ],
            int(MAX_HISTORICAL_BLOCK_HASHES),
        ),
        justifications_roots=List(
            [
                Bytes32(b"\x00" * 32),
                Bytes32(b"\x01" * 32),
            ],
            int(MAX_HISTORICAL_BLOCK_HASHES),
        ),
        justifications_validators=Bitlist(
            int(MAX_HISTORICAL_BLOCK_HASHES * VALIDATOR_REGISTRY_LIMIT)
        ),
    )
