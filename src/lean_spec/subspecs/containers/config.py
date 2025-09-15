"""Consensus Configuration Container."""

from lean_spec.types import Uint64
from lean_spec.types.container import Container


class Config(Container):
    """
    Holds temporary configuration properties for simplified consensus.

    Note: These fields support a simplified round-robin block production
    in the absence of more complex mechanisms like RANDAO or deposits.
    """

    num_validators: Uint64
    """The total number of validators in the network."""

    genesis_time: Uint64
    """The timestamp of the genesis block."""
