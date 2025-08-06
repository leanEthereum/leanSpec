"""
A `State` is a collection of metadata that describes the current state of the
Lean Consensus chain. It contains information about the latest justified and
finalized blocks, as well as the historical block hashes and justified slots.

It is used to verify the integrity of the chain and to ensure that the chain is
progressing correctly.
"""

from dataclasses import dataclass
from remerkleable.basic import uint64
from remerkleable.bitfields import Bitlist
from remerkleable.byte_arrays import Bytes32
from remerkleable.complex import List
from pydantic import BaseModel, ConfigDict

from preset import MAX_HISTORICAL_BLOCK_HASHES, VALIDATOR_REGISTRY_LIMIT

@dataclass
class State(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Diverged from 3SF-mini.py:
    #   - Removed `config: Config` from the state
    #   - Using uint64 instead of native int for all fields
    #   - Using Bytes32 instead of native str for all fields

    latest_justified_hash: Bytes32
    latest_justified_slot: uint64

    latest_finalized_hash: Bytes32
    latest_finalized_slot: uint64

    historical_block_hashes: List[Bytes32, MAX_HISTORICAL_BLOCK_HASHES]
    justified_slots: List[bool, MAX_HISTORICAL_BLOCK_HASHES]

    # Diverged from 3SF-mini.py:
    #   - Flattened `justifications: Dict[str, List[bool]]` for SSZ compatibility
    justifications_roots: List[Bytes32, MAX_HISTORICAL_BLOCK_HASHES]
    justifications_validators: Bitlist[MAX_HISTORICAL_BLOCK_HASHES * VALIDATOR_REGISTRY_LIMIT]
