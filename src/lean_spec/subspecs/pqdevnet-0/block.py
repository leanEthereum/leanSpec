"""
A `Block` is a single link in the Lean Consensus chain. Each `Block` contains
associated metadata like the slot number, parent block hash and votes.

Together, these blocks form a cryptographically secure journal recording the
history of all state transitions that have happened since the genesis of the
chain.
"""

from dataclasses import dataclass

from ethereum_types.bytes import Bytes32
from ethereum_types.numeric import U64
from pydantic import BaseModel, ConfigDict
from ssz.sedes.list import List

from .preset import VALIDATOR_REGISTRY_LIMIT
from .vote import Vote


@dataclass
class Block(BaseModel):
    """A single block in the Lean Consensus chain."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    slot: U64
    parent: Bytes32
    votes: List[Vote, VALIDATOR_REGISTRY_LIMIT]
    # Diverged from 3SF-mini.py: Removed Optional from `state_root`
    state_root: Bytes32
