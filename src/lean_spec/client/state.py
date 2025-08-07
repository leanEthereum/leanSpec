"""
A `State` is a collection of metadata that describes the current state of the
Lean Consensus chain. It contains information about the latest justified and
finalized blocks, as well as the historical block hashes and justified slots.

It is used to verify the integrity of the chain and to ensure that the chain is
progressing correctly.
"""

from dataclasses import dataclass

from ethereum_types.bytes import Bytes32
from ethereum_types.numeric import U64
from pydantic import BaseModel, ConfigDict
from ssz.sedes.bitlist import Bitlist
from ssz.sedes.list import List

from .preset import MAX_HISTORICAL_BLOCK_HASHES, VALIDATOR_REGISTRY_LIMIT


@dataclass
class State(BaseModel):
    """Represents the current state of the Lean Consensus chain."""
    
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Diverged from 3SF-mini.py:
    #   - Removed `config: Config` from the state
    #   - Using `U64` instead of native int for all fields
    #   - Using `Bytes32` instead of native str for all fields

    latest_justified_hash: Bytes32
    latest_justified_slot: U64

    latest_finalized_hash: Bytes32
    latest_finalized_slot: U64

    historical_block_hashes: List[Bytes32, MAX_HISTORICAL_BLOCK_HASHES]
    justified_slots: List[bool, MAX_HISTORICAL_BLOCK_HASHES]

    # Diverged from 3SF-mini.py:
    #   - Flattened `justifications: Dict[str, List[bool]]` for SSZ
    justifications_roots: List[Bytes32, MAX_HISTORICAL_BLOCK_HASHES]
    justifications_validators: Bitlist[
        MAX_HISTORICAL_BLOCK_HASHES * VALIDATOR_REGISTRY_LIMIT
    ]
