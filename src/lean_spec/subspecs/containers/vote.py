"""Vote Containers."""

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, Uint64
from lean_spec.types.container import Container

from .checkpoint import Checkpoint


class Vote(Container):
    """Represents a validator's vote for chain head."""

    validator_id: Uint64
    """The index of the voting validator."""

    slot: Slot
    """The slot for which this vote is cast."""

    head: Checkpoint
    """The validator's perceived head of the chain."""

    target: Checkpoint
    """The justified checkpoint the validator is voting for."""

    source: Checkpoint
    """The last justified checkpoint known to the validator."""


class SignedVote(Container):
    """A container for a vote and its corresponding signature."""

    data: Vote
    """The vote data."""

    signature: Bytes32
    """
    The signature of the vote data.

    Note: Bytes32 is a placeholder; the actual signature is much larger.
    """
