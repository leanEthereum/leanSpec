"""Consensus Configuration Container."""

from lean_spec.types import Uint64
from lean_spec.types.container import Container


class Config(Container):
    """
    Holds temporary configuration properties for simplified consensus.

    Note: These fields support a simplified round-robin block production
    in the absence of more complex mechanisms like RANDAO or deposits.
    """

    genesis_time: Uint64
    """The timestamp of the genesis block."""

    min_activation_delay: Uint64 = Uint64(8)
    """Minimum slots before a validator deposit activates."""

    min_exit_delay: Uint64 = Uint64(8)
    """Minimum slots before a validator exit is removed."""

    max_activations_per_slot: Uint64 = Uint64(4)
    """Maximum validators that can activate in one slot."""

    max_exits_per_slot: Uint64 = Uint64(4)
    """Maximum validators that can exit in one slot."""
