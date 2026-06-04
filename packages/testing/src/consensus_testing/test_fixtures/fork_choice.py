"""
Fork choice test fixture format.

Tests fork choice scenarios through time-ordered events.
Validates Store responses to blocks, attestations, and time progression.
"""

from __future__ import annotations

from typing import ClassVar, Self

from pydantic import Field, model_validator

from consensus_testing.keys import XmssKeyManager
from consensus_testing.test_fixtures.base import BaseConsensusFixture
from consensus_testing.test_types import (
    AttestationStep,
    BlockStep,
    ForkChoiceStep,
    GossipAggregatedAttestationStep,
    TickStep,
)
from lean_spec.node.chain.clock import SlotClock
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Interval, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestations,
    Block,
    BlockBody,
    State,
    Validators,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec


class ForkChoiceTest(BaseConsensusFixture):
    """
    Test fixture for event-driven fork choice scenarios.

    Fork choice tests simulate a node processing events over time.
    The Store maintains all chain state needed to compute the head.

    Test structure:

    1. Initialize Store from anchor state and block
    2. Process steps in order (tick, block, attestation)
    3. Validate Store state against expected values

    Labels allow building forks.
    Give a block a label, then reference it as a parent in later blocks.
    """

    format_name: ClassVar[str] = "fork_choice_test"
    """Identifier used in fixture output paths and metadata."""

    description: ClassVar[str] = "Tests event-driven fork choice through Store operations"
    """Human-readable summary for fixture documentation."""

    anchor_state: State | None = None
    """
    Initial trusted consensus state.

    Most tests start from genesis.
    The pytest fixture provides this automatically.
    """

    anchor_block: Block | None = None
    """
    Initial trusted block (unsigned).

    Derived from anchor state if not provided.
    """

    steps: list[ForkChoiceStep]
    """
    Sequence of fork choice events to process.

    Events execute in order.
    Store state carries forward between steps.
    Each step can validate Store state via checks.
    """

    anchor_valid: bool = Field(default=True, exclude=True)
    """
    Whether Store.from_anchor is expected to succeed.

    Default True covers every normal test.
    Set False to assert that store initialization itself must fail,
    e.g. when the anchor block and state are inconsistent.

    Excluded from JSON output: configures the test runner, not the test
    vector that clients consume.
    """

    expected_anchor_error: str | None = Field(default=None, exclude=True)
    """
    Substring required in the raised exception when anchor_valid is False.

    Ignored when anchor_valid is True.
    Used to pin the failure to a specific precondition rather than any crash.
    When None, any AssertionError from Store.from_anchor is accepted.

    Excluded from JSON output: configures the test runner, not the test
    vector that clients consume.
    """

    max_slot: Slot | None = None
    """
    Maximum slot for XMSS key validity.

    Calculated from steps if not provided.
    XMSS keys need precomputation up to this slot.
    """

    @model_validator(mode="after")
    def set_anchor_block_default(self) -> Self:
        """
        Auto-generate anchor block from anchor state if not provided.

        Most tests start from genesis.
        Deriving the anchor block from state reduces boilerplate.
        """
        if self.anchor_block is None and self.anchor_state is not None:
            # Build a minimal genesis block from the state's header fields.
            #
            # The state already contains the block header.
            # We extract its fields to create a matching Block.
            self.anchor_block = Block(
                slot=self.anchor_state.latest_block_header.slot,
                proposer_index=self.anchor_state.latest_block_header.proposer_index,
                parent_root=self.anchor_state.latest_block_header.parent_root,
                state_root=hash_tree_root(self.anchor_state),
                body=BlockBody(attestations=AggregatedAttestations(data=[])),
            )
        return self

    @model_validator(mode="after")
    def set_max_slot_default(self) -> Self:
        """
        Auto-calculate max slot from steps if not provided.

        XMSS keys require precomputation.
        We scan steps to find the highest slot needed.
        """
        if self.max_slot is None:
            max_slot_value = Slot(0)

            # Find the maximum slot across all block and attestation steps.
            #
            # XMSS signatures are slot-dependent.
            # Keys must be generated up to this slot before signing.
            for step in self.steps:
                if isinstance(step, BlockStep):
                    max_slot_value = max(max_slot_value, step.block.slot)
                elif isinstance(step, AttestationStep):
                    max_slot_value = max(max_slot_value, step.attestation.slot)
                elif isinstance(step, GossipAggregatedAttestationStep):
                    max_slot_value = max(max_slot_value, step.attestation.slot)

            self.max_slot = max_slot_value

        return self

    def make_fixture(self) -> Self:
        """
        Generate the fixture by running the spec's Store.

        Executes each step against the actual specification and validates checks.

        Returns:
            The validated fixture (self, since steps contain the test).

        Raises:
            AssertionError: If any step fails unexpectedly or checks mismatch.
        """
        # Precondition validation
        #
        # Pydantic validators should have populated these fields.
        # These assertions guard against misuse.
        assert self.anchor_state is not None, "anchor state must be set before making fixture"
        assert self.anchor_block is not None, "anchor block must be set before making fixture"
        assert self.max_slot is not None, "max slot must be set before making fixture"

        spec = LstarSpec()

        # Expected anchor-init failure path.
        #
        # When anchor_valid is False, the test asserts that Store.from_anchor
        # rejects the given (state, block) pair. The public_key sync that normally
        # fixes up the anchor block's state root is skipped, since that would
        # mask the very inconsistency under test.
        if not self.anchor_valid:
            assert self.steps == [], (
                "steps must be empty when anchor_valid is False: "
                "Store.from_anchor is expected to fail before any step can run"
            )
            try:
                spec.create_store(
                    self.anchor_state,
                    self.anchor_block,
                    validator_index=ValidatorIndex(0),
                )
            except AssertionError as e:
                if self.expected_anchor_error is not None and self.expected_anchor_error not in str(
                    e
                ):
                    raise AssertionError(
                        "Store.from_anchor failed with wrong error.\n"
                        f"  Expected error containing: {self.expected_anchor_error!r}\n"
                        f"  Actual error: {e!r}"
                    ) from e
                return self

            raise AssertionError("Store.from_anchor was expected to fail but succeeded")

        # Key manager setup
        #
        # XMSS keys are expensive to generate.
        # The shared key manager caches keys across tests.
        # Tests requiring higher max slot trigger key expansion.
        key_manager = XmssKeyManager.shared(max_slot=self.max_slot)

        # Validator public_key synchronization
        #
        # Test states use placeholder public_keys.
        # We must replace them with the key manager's actual keys.
        # Otherwise signature verification will fail.
        updated_validators = []
        for i, validator in enumerate(self.anchor_state.validators):
            index = ValidatorIndex(i)
            attestation_public_key, proposal_public_key = key_manager.get_public_keys(index)
            updated_validators.append(
                validator.model_copy(
                    update={
                        "attestation_public_key": attestation_public_key.encode_bytes(),
                        "proposal_public_key": proposal_public_key.encode_bytes(),
                    }
                )
            )

        # Updating validators changes the state root.
        # We must also update the anchor block to match.
        self.anchor_state.validators = Validators(data=updated_validators)
        self.anchor_block.state_root = hash_tree_root(self.anchor_state)

        # Store initialization
        #
        # The Store is the node's local view of the chain.
        # It starts from a trusted anchor (usually genesis).
        store = spec.create_store(
            self.anchor_state,
            self.anchor_block,
            validator_index=ValidatorIndex(0),
        )

        # Block registry for fork creation
        #
        # Labels let tests reference blocks by name.
        # This enables building forks: "build block B with parent A".
        # The "genesis" label is always available.
        self._block_registry: dict[str, Block] = {"genesis": self.anchor_block}

        # Step processing loop
        #
        # Process each step against the Store.
        # Store follows immutable pattern: each method returns a new Store.
        for i, step in enumerate(self.steps):
            old_head = store.head
            try:
                match step:
                    case TickStep():
                        # Time advancement may trigger slot boundaries.
                        # At slot boundaries, pending attestations may become active.
                        # Always act as aggregator to ensure gossip signatures are aggregated
                        if step.interval is not None:
                            # Tests that care about exact interval semantics can
                            # target the store's internal interval clock directly.
                            target_interval = Interval(step.interval)
                        else:
                            assert step.time is not None
                            # TickStep.time is a Unix timestamp in seconds.
                            # The slot clock converts it to intervals since genesis.
                            target_interval = SlotClock(
                                genesis_time=store.config.genesis_time,
                                time_fn=lambda t=step.time: float(t),
                            ).total_intervals()
                        store, _ = spec.on_tick(
                            store,
                            target_interval,
                            has_proposal=step.has_proposal,
                            is_aggregator=True,
                        )

                    case BlockStep():
                        # Build a complete signed block from the lightweight spec.
                        # The spec contains minimal fields; we fill the rest.
                        signed_block, store = step.block.build_signed_block_with_store(
                            store, self._block_registry, key_manager, self.lean_env
                        )

                        # Store the filled block for serialization.
                        block = signed_block.block
                        step._filled_block = block

                        # Register labeled blocks for fork building.
                        # Later blocks can reference this one as their parent.
                        if step.block.label is not None:
                            if step.block.label in self._block_registry:
                                raise ValueError(
                                    f"Step {i}: duplicate label '{step.block.label}' - "
                                    f"labels must be unique within a test"
                                )
                            self._block_registry[step.block.label] = block

                        # Advance time to the block's slot.
                        # Store rejects blocks from the future.
                        # This tick includes a block (has proposal).
                        # Always act as aggregator to ensure gossip signatures are aggregated
                        target_interval = Interval.from_slot(block.slot)
                        store, _ = spec.on_tick(
                            store, target_interval, has_proposal=True, is_aggregator=True
                        )

                        # Process the block through Store.
                        # This validates, applies state transition, and updates the store's head.
                        store = spec.on_block(store, signed_block)

                    case AttestationStep():
                        # Process a gossip attestation.
                        # Gossip attestations arrive outside of blocks.
                        # They influence the fork choice weight calculation.
                        signed_attestation = step.attestation.build_signed(
                            self._block_registry,
                            key_manager,
                            store,
                            self.anchor_block,
                            step.valid,
                        )
                        step._filled_attestation = signed_attestation
                        store = spec.on_gossip_attestation(
                            store,
                            signed_attestation,
                            is_aggregator=step.is_aggregator,
                        )

                    case GossipAggregatedAttestationStep():
                        signed_aggregated = step.attestation.build_signed(
                            self._block_registry,
                            store.states[store.head],
                            key_manager,
                        )
                        step._filled_attestation = signed_aggregated
                        store = spec.on_gossip_aggregated_attestation(store, signed_aggregated)

                    case _:
                        raise ValueError(f"Step {i}: unknown step type {type(step).__name__}")

                # Validate Store state if checks are provided.
                if step.checks is not None:
                    filled_block = step._filled_block if isinstance(step, BlockStep) else None
                    step.checks.validate_against_store(
                        store,
                        step_index=i,
                        block_registry=self._block_registry,
                        filled_block=filled_block,
                        old_head=old_head,
                    )

            except Exception as e:
                # Handle expected failures.
                # Steps marked valid=False should raise exceptions.
                if step.valid:
                    raise AssertionError(
                        f"Step {i} ({type(step).__name__}) failed unexpectedly: {e}"
                    ) from e

                # Verify the failure reason matches when specified.
                if step.expected_error is not None and step.expected_error not in str(e):
                    raise AssertionError(
                        f"Step {i} ({type(step).__name__}) failed with wrong error.\n"
                        f"  Expected error containing: {step.expected_error!r}\n"
                        f"  Actual error: {e!r}"
                    ) from e

                continue

            # Handle unexpected success.
            # If we expected failure but the step succeeded, that's a test bug.
            if not step.valid:
                raise AssertionError(
                    f"Step {i} ({type(step).__name__}) succeeded but expected failure"
                )

        # Return self (fixture is already complete)
        return self
