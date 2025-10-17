"""Fork choice test fixture format."""

from typing import Any, ClassVar, Dict, List, Literal

from pydantic import BaseModel

from lean_spec.subspecs.containers.block.block import SignedBlock
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.containers.vote import SignedVote

from .base import BaseConsensusFixture


class ForkChoiceStep(BaseModel):
    """
    Single fork choice event step.

    Represents one action in a fork choice test sequence.
    """

    step_type: Literal["tick", "block", "attestation", "check"]
    """Type of fork choice event."""

    # For tick steps
    time: int | None = None
    """Time to advance to (unix timestamp or slot time)."""

    # For block steps
    block: SignedBlock | None = None
    """Block to process."""

    valid: bool = True
    """Whether this step is expected to succeed."""

    # For attestation steps (gossip, not from blocks)
    attestation: SignedVote | None = None
    """Attestation (SignedVote) to process from gossip."""

    # For check steps
    assertions: Dict[str, Any] | None = None
    """
    Assertions about store state.

    Examples:
        {"head.slot": 32, "head.root": "0xabc..."}
        {"justified_checkpoint.epoch": 3}
        {"finalized_checkpoint.epoch": 2}
    """


class ForkChoiceTest(BaseConsensusFixture):
    """
    Test fixture for event-driven fork choice scenarios.

    Tests the fork choice Store through a sequence of events:
    - on_tick: Time advancement
    - on_block: Block arrival
    - on_attestation: Attestation arrival (from gossip)
    - checks: Store state validation

    This tests LMD-GHOST algorithm, proposer boost, reorgs, and
    timing-sensitive behavior.

    Structure:
        anchor_state: Initial trusted state
        anchor_block: Initial trusted block
        steps: Sequence of events and checks
    """

    format_name: ClassVar[str] = "fork_choice_test"
    description: ClassVar[str] = "Tests event-driven fork choice through Store operations"

    anchor_state: State
    """The initial trusted consensus state."""

    anchor_block: SignedBlock
    """The initial trusted block."""

    steps: List[ForkChoiceStep]
    """
    Sequence of fork choice events to process.

    Events are processed in order, with store state carrying forward.
    """
