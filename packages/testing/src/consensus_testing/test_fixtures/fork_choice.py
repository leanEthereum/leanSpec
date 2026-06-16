"""Fork choice test fixture format."""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field

from consensus_testing.genesis import generate_pre_state, reconstruct_block_from_header
from consensus_testing.keys import XmssKeyManager
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from consensus_testing.test_types import (
    AttestationStep,
    BlockStep,
    FilledAttestationStep,
    FilledBlockStep,
    FilledForkChoiceStep,
    FilledGossipAggregatedAttestationStep,
    FilledTickStep,
    ForkChoiceStep,
    GossipAggregatedAttestationStep,
    StoreSnapshot,
    TickStep,
)
from lean_spec.node.chain.clock import SlotClock
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import (
    Interval,
    RejectionReason,
    Slot,
    SpecRejectionError,
    ValidatorIndex,
)
from lean_spec.spec.forks.lstar.containers import (
    AggregationError,
    Block,
    SignedAggregatedAttestation,
    SignedAttestation,
    State,
    Validators,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec


class ForkChoiceFixture(BaseConsensusFixture):
    """
    Emitted vector for event-driven fork choice scenarios.

    JSON output: anchorState, anchorBlock, steps, maxSlot.
    """

    anchor_state: State
    """Initial trusted consensus state."""

    anchor_block: Block
    """Initial trusted block (unsigned)."""

    steps: list[FilledForkChoiceStep]
    """Emitted fork choice events, one per authored step."""

    max_slot: Slot
    """Maximum slot for XMSS key validity."""


class ForkChoiceTest(BaseTestSpec):
    """
    Spec for event-driven fork choice scenarios.

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

    anchor_state: State = Field(default_factory=generate_pre_state)
    """
    Initial trusted consensus state.

    Defaults to the standard genesis state.
    Spell it out only when the test needs a non-default anchor.
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

    anchor_valid: bool = True
    """
    Whether Store.from_anchor is expected to succeed.

    Default True covers every normal test.
    Set False to assert that store initialization itself must fail,
    e.g. when the anchor block and state are inconsistent.
    The base expected rejection field then refines the required failure.
    """

    max_slot: Slot | None = None
    """
    Maximum slot for XMSS key validity.

    Calculated from steps if not provided.
    XMSS keys need precomputation up to this slot.
    """

    def _resolved_anchor_block(self) -> Block:
        """
        Return the authored anchor block, or derive one from the anchor state.

        Most tests start from genesis.
        Deriving the anchor block from state reduces boilerplate.
        """
        if self.anchor_block is not None:
            return self.anchor_block
        # Build a minimal genesis block from the state's header fields.
        #
        # The state already contains the block header.
        # We extract its fields to create a matching Block.
        return reconstruct_block_from_header(self.anchor_state)

    def _resolved_max_slot(self) -> Slot:
        """
        Return the authored max slot, or compute it from the steps.

        XMSS keys require precomputation.
        We scan steps to find the highest slot needed.
        """
        if self.max_slot is not None:
            return self.max_slot

        # Find the maximum slot across all block and attestation steps.
        #
        # XMSS signatures are slot-dependent.
        # Keys must be generated up to this slot before signing.
        slots_needing_keys = (
            step.block.slot if isinstance(step, BlockStep) else step.attestation.slot
            for step in self.steps
            if isinstance(step, (BlockStep, AttestationStep, GossipAggregatedAttestationStep))
        )
        return max(slots_needing_keys, default=Slot(0))

    def generate(self) -> ForkChoiceFixture:
        """
        Generate the fixture by running the spec's Store.

        Executes each step against the actual specification and validates checks.

        Returns:
            The emitted vector with one filled step per authored step.

        Raises:
            AssertionError: If any step fails unexpectedly or checks mismatch.
        """
        spec = LstarSpec()
        anchor_block = self._resolved_anchor_block()
        max_slot = self._resolved_max_slot()

        # Expected anchor-init failure path.
        #
        # When anchor_valid is False, the test asserts that Store.from_anchor
        # rejects the given (state, block) pair. The public_key sync that normally
        # fixes up the anchor block's state root is skipped, since that would
        # mask the very inconsistency under test.
        if not self.anchor_valid:
            return self._generate_invalid_anchor(spec, anchor_block, max_slot)

        # Key manager setup
        #
        # XMSS keys are expensive to generate.
        # The shared key manager caches keys across tests.
        # Tests requiring higher max slot trigger key expansion.
        key_manager = XmssKeyManager.shared(max_slot=max_slot)

        # Validator public_key synchronization
        #
        # Test states use placeholder public_keys.
        # We must replace them with the key manager's actual keys.
        # Otherwise signature verification will fail.
        updated_validators = []
        for validator_position, validator in enumerate(self.anchor_state.validators):
            validator_index = ValidatorIndex(validator_position)
            attestation_public_key, proposal_public_key = key_manager.get_public_keys(
                validator_index
            )
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
        anchor_state = self.anchor_state.model_copy(
            update={"validators": Validators(data=updated_validators)}
        )
        anchor_block = anchor_block.model_copy(update={"state_root": hash_tree_root(anchor_state)})

        # Store initialization
        #
        # The Store is the node's local view of the chain.
        # It starts from a trusted anchor (usually genesis).
        store = spec.create_store(
            anchor_state,
            anchor_block,
            validator_index=ValidatorIndex(0),
        )

        # Block registry for fork creation
        #
        # Labels let tests reference blocks by name.
        # This enables building forks: "build block B with parent A".
        # The "genesis" label is always available.
        block_registry: dict[str, Block] = {"genesis": anchor_block}

        # Step processing loop
        #
        # Process each step against the Store.
        # Store follows immutable pattern: each method returns a new Store.
        filled_steps: list[FilledForkChoiceStep] = []
        for step_index, step in enumerate(self.steps):
            old_head = store.head
            rejection_reason: RejectionReason | None = None
            store_snapshot: StoreSnapshot
            filled_block: Block | None = None
            filled_attestation: SignedAttestation | None = None
            filled_aggregated: SignedAggregatedAttestation | None = None
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
                        # A step expecting the unknown-parent rejection may point
                        # the block at a parent the store never imported.
                        # The builder then skips the state transition and hands
                        # the block straight to the spec, where that guard fires.
                        deliver_unknown_parent = (
                            step.expected_rejection is not None
                            and step.expected_rejection.reason
                            is RejectionReason.UNKNOWN_PARENT_BLOCK
                        )

                        # Build a complete signed block from the lightweight spec.
                        # The spec contains minimal fields; we fill the rest.
                        signed_block, store = step.block.build_signed_block_with_store(
                            store,
                            block_registry,
                            key_manager,
                            deliver_unknown_parent=deliver_unknown_parent,
                        )
                        filled_block = signed_block.block

                        # Register labeled blocks for fork building.
                        # Later blocks can reference this one as their parent.
                        if step.block.label is not None:
                            if step.block.label in block_registry:
                                raise ValueError(
                                    f"Step {step_index}: duplicate label '{step.block.label}' - "
                                    f"labels must be unique within a test"
                                )
                            block_registry[step.block.label] = filled_block

                        # Advance time to the block's slot unless the test
                        # delivers the block ahead of the store clock.
                        # This tick includes a block (has proposal).
                        # Always act as aggregator to ensure gossip signatures are aggregated
                        if step.tick_to_slot:
                            target_interval = Interval.from_slot(filled_block.slot)
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
                        filled_attestation = step.attestation.build_signed(
                            block_registry,
                            key_manager,
                            store,
                            anchor_block,
                            step.valid,
                        )
                        store = spec.on_gossip_attestation(
                            store,
                            filled_attestation,
                            is_aggregator=step.is_aggregator,
                        )

                    case GossipAggregatedAttestationStep():
                        filled_aggregated = step.attestation.build_signed(
                            block_registry,
                            store.states[store.head],
                            key_manager,
                        )
                        store = spec.on_gossip_aggregated_attestation(store, filled_aggregated)

                    case _:
                        raise ValueError(
                            f"Step {step_index}: unknown step type {type(step).__name__}"
                        )

                # Record the canonical store observables for this step.
                # Clients replay the step and must reproduce every field.
                # Authored checks below remain a human-readable overlay.
                store_snapshot = StoreSnapshot.from_store(store)

                # Validate Store state if checks are provided.
                if step.checks is not None:
                    step.checks.validate_against_store(
                        store,
                        step_index=step_index,
                        block_registry=block_registry,
                        filled_block=filled_block,
                        old_head=old_head,
                    )

            except (SpecRejectionError, AggregationError) as exception:
                # Handle expected failures.
                # Steps marked valid=False should raise spec rejections.
                # Harness bugs raise other types and propagate unswallowed.
                if step.valid:
                    raise AssertionError(
                        f"Step {step_index} ({type(step).__name__}) "
                        f"failed unexpectedly: {exception}"
                    ) from exception

                rejection_reason = self.check_rejection_against_expectation(
                    step.expected_rejection,
                    exception,
                    f"Step {step_index} ({type(step).__name__})",
                )

                # The rejected call returned nothing, so the store is unchanged.
                # Snapshot it anyway: clients must verify the no-op.
                store_snapshot = StoreSnapshot.from_store(store)

            else:
                # Handle unexpected success.
                # If we expected failure but the step succeeded, that's a test bug.
                if not step.valid:
                    raise AssertionError(
                        f"Step {step_index} ({type(step).__name__}) succeeded but expected failure"
                    )

            # Emit the filled counterpart of this step.
            # Expected failures keep their built payload and the unchanged store.
            match step:
                case TickStep():
                    filled_steps.append(
                        FilledTickStep(
                            valid=step.valid,
                            rejection_reason=rejection_reason,
                            checks=step.checks,
                            store_snapshot=store_snapshot,
                            time=step.time,
                            interval=step.interval,
                            has_proposal=step.has_proposal,
                        )
                    )
                case BlockStep():
                    assert filled_block is not None, (
                        f"Step {step_index}: the step failed before its block was built"
                    )
                    filled_steps.append(
                        FilledBlockStep(
                            valid=step.valid,
                            rejection_reason=rejection_reason,
                            checks=step.checks,
                            store_snapshot=store_snapshot,
                            tick_to_slot=step.tick_to_slot,
                            block=filled_block,
                            block_root_label=step.block.label,
                        )
                    )
                case AttestationStep():
                    assert filled_attestation is not None, (
                        f"Step {step_index}: the step failed before its attestation was built"
                    )
                    filled_steps.append(
                        FilledAttestationStep(
                            valid=step.valid,
                            rejection_reason=rejection_reason,
                            checks=step.checks,
                            store_snapshot=store_snapshot,
                            attestation=filled_attestation,
                            is_aggregator=step.is_aggregator,
                        )
                    )
                case GossipAggregatedAttestationStep():
                    assert filled_aggregated is not None, (
                        f"Step {step_index}: the step failed before its aggregate was built"
                    )
                    filled_steps.append(
                        FilledGossipAggregatedAttestationStep(
                            valid=step.valid,
                            rejection_reason=rejection_reason,
                            checks=step.checks,
                            store_snapshot=store_snapshot,
                            attestation=filled_aggregated,
                        )
                    )

        return ForkChoiceFixture(
            anchor_state=anchor_state,
            anchor_block=anchor_block,
            steps=filled_steps,
            max_slot=max_slot,
        )

    def _generate_invalid_anchor(
        self,
        spec: LstarSpec,
        anchor_block: Block,
        max_slot: Slot,
    ) -> ForkChoiceFixture:
        """
        Assert that store initialization rejects the anchor pair.

        Returns:
            The emitted vector carrying the rejection reason and no steps.

        Raises:
            AssertionError: If initialization succeeds or fails for the wrong reason.
        """
        assert self.steps == [], (
            "steps must be empty when anchor_valid is False: "
            "Store.from_anchor is expected to fail before any step can run"
        )
        # A vector saying only "reject this anchor" lets a client
        # reject for the wrong reason and still pass.
        assert self.expected_rejection is not None, (
            "anchor_valid=False requires expected_rejection to be set"
        )
        try:
            spec.create_store(
                self.anchor_state,
                anchor_block,
                validator_index=ValidatorIndex(0),
            )
        except SpecRejectionError as exception:
            # Emit the language-neutral reason clients assert against.
            return ForkChoiceFixture(
                anchor_state=self.anchor_state,
                anchor_block=anchor_block,
                steps=[],
                max_slot=max_slot,
                rejection_reason=self.check_rejection_against_expectation(
                    self.expected_rejection,
                    exception,
                    "Store.from_anchor",
                ),
            )

        raise AssertionError("Store.from_anchor was expected to fail but succeeded")
