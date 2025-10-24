"""Fork choice test fixture format."""

from typing import ClassVar, List

from pydantic import model_validator

from lean_spec.subspecs.chain.config import SECONDS_PER_INTERVAL, SECONDS_PER_SLOT
from lean_spec.subspecs.containers.block.block import Block, BlockBody
from lean_spec.subspecs.containers.block.types import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.types import Uint64

from ..test_types import AttestationStep, BlockStep, ForkChoiceStep, TickStep
from .base import BaseConsensusFixture


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

    anchor_block: Block | None = None
    """
    The initial trusted block (unsigned).

    If not provided, will be auto-generated from anchor_state's latest_block_header.
    This is typically the genesis block.
    """

    steps: List[ForkChoiceStep]
    """
    Sequence of fork choice events to process.

    Events are processed in order, with store state carrying forward.
    """

    @model_validator(mode="after")
    def set_anchor_block_default(self) -> "ForkChoiceTest":
        """
        Auto-generate anchor_block from anchor_state if not provided.

        This creates a block from the state's latest_block_header, which is
        typically the genesis block. The state_root is set to the hash of the
        anchor_state itself.
        """
        if self.anchor_block is None:
            self.anchor_block = Block(
                slot=self.anchor_state.latest_block_header.slot,
                proposer_index=self.anchor_state.latest_block_header.proposer_index,
                parent_root=self.anchor_state.latest_block_header.parent_root,
                state_root=hash_tree_root(self.anchor_state),
                body=BlockBody(attestations=Attestations(data=[])),
            )
        return self

    def make_fixture(self) -> "ForkChoiceTest":
        """
        Generate the fixture by running the spec's Store.

        This validates the test by:
        1. Initializing Store from anchor_state and anchor_block
        2. Processing each step through Store methods
        3. Validating check assertions against Store state

        Returns:
        -------
        ForkChoiceTest
            The validated fixture (self, since steps contain the test).

        Raises:
        ------
        AssertionError
            If any step fails unexpectedly or checks don't match Store state.
        """
        # Initialize Store from anchor
        # anchor_block is guaranteed to be set by the validator
        assert self.anchor_block is not None, "anchor_block must be set"
        store = Store.get_forkchoice_store(
            state=self.anchor_state,
            anchor_block=self.anchor_block,
        )

        # Process each step
        for i, step in enumerate(self.steps):
            try:
                if isinstance(step, TickStep):
                    # Advance time
                    store.advance_time(Uint64(step.time), has_proposal=False)

                elif isinstance(step, BlockStep):
                    # Automatically advance time to block's slot before processing
                    block = step.block.message
                    block_time = store.config.genesis_time + block.slot * Uint64(SECONDS_PER_SLOT)

                    # Advance time slot by slot until we reach block time
                    while store.time < block_time:
                        # Compute current slot from store time
                        current_slot = Slot(store.time // SECONDS_PER_INTERVAL)
                        next_slot = current_slot + Slot(1)
                        next_time = store.config.genesis_time + next_slot * Uint64(SECONDS_PER_SLOT)
                        store.advance_time(next_time, has_proposal=False)

                    # Process the block (which calls state_transition internally)
                    # state_transition will process slots, so the state will be advanced
                    store.process_block(step.block)

                elif isinstance(step, AttestationStep):
                    # Process attestation from gossip (not from block)
                    store.process_attestation(step.attestation, is_from_block=False)

                else:
                    raise ValueError(f"Step {i}: unknown step type {type(step).__name__}")

                # Validate checks if provided
                if step.checks is not None:
                    step.checks.validate_against_store(store, step_index=i)

            except Exception as e:
                if step.valid:
                    # Expected to succeed but failed
                    raise AssertionError(
                        f"Step {i} ({type(step).__name__}) failed unexpectedly: {e}"
                    ) from e
                # Expected to fail, continue
                continue

            # If we expected failure but succeeded, that's an error
            if not step.valid:
                raise AssertionError(
                    f"Step {i} ({type(step).__name__}) succeeded but expected failure"
                )

        # Return self (fixture is already complete)
        return self
