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

    latest_justified_hash: Bytes32
    latest_justified_slot: uint64

    latest_finalized_hash: Bytes32
    latest_finalized_slot: uint64

    historical_block_hashes: List[Bytes32, MAX_HISTORICAL_BLOCK_HASHES]
    justified_slots: List[bool, MAX_HISTORICAL_BLOCK_HASHES]

    # Originally in 3SF-mini: `justifications: Dict[str, List[bool]]`
    justifications_roots: List[Bytes32, MAX_HISTORICAL_BLOCK_HASHES]

    # Capacity should be enough for a flattened `justifications[root][validator_id]`
    justifications_roots_validators: Bitlist[MAX_HISTORICAL_BLOCK_HASHES * VALIDATOR_REGISTRY_LIMIT]
