"""Fork choice test fixture format."""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field
from ssz import hash_tree_root

from consensus_testing.genesis import build_genesis_state, reconstruct_block_from_header
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
    """Emitted vector for event-driven fork choice scenarios."""

    anchor_state: State
    """Initial trusted consensus state."""

    anchor_block: Block
    """Initial trusted block (unsigned)."""

    steps: list[FilledForkChoiceStep]
    """Emitted fork choice events, one per authored step."""

    max_slot: Slot
    """Maximum slot for XMSS key validity."""


class ForkChoiceTest(BaseTestSpec):
    """Spec for event-driven fork choice scenarios, with the store carrying all chain state."""

    format_name: ClassVar[str] = "fork_choice_test"
    """Identifier used in fixture output paths and metadata."""

    description: ClassVar[str] = "Tests event-driven fork choice through Store operations"
    """Human-readable summary for fixture documentation."""

    anchor_state: State = Field(default_factory=build_genesis_state)
    """Initial trusted consensus state, defaulting to genesis."""

    anchor_block: Block | None = None
    """Initial trusted block, derived from the anchor state when absent."""

    steps: list[ForkChoiceStep]
    """Fork choice events to process in order, carrying store state forward."""

    anchor_valid: bool = True
    """Whether store initialization is expected to succeed."""

    max_slot: Slot | None = None
    """Highest slot XMSS keys must cover, computed from the steps when absent."""

    def _resolved_anchor_block(self) -> Block:
        """Return the authored anchor block, or rebuild one from the anchor state's header."""
        if self.anchor_block is not None:
            return self.anchor_block
        return reconstruct_block_from_header(self.anchor_state)

    def _resolved_max_slot(self) -> Slot:
        """Return the authored max slot, or the highest slot the steps need keys for."""
        if self.max_slot is not None:
            return self.max_slot

        # XMSS signatures are slot-dependent, so keys must exist up to the highest signed slot.
        def slot_needing_keys(step: ForkChoiceStep) -> Slot | None:
            match step:
                case BlockStep():
                    return step.block.slot
                case AttestationStep() | GossipAggregatedAttestationStep():
                    return step.attestation.slot
                case _:
                    return None

        return max(
            (slot for step in self.steps if (slot := slot_needing_keys(step)) is not None),
            default=Slot(0),
        )

    def generate(self) -> ForkChoiceFixture:
        """
        Run each step against the spec's store and emit one filled step per authored step.

        Raises:
            AssertionError: If any step fails unexpectedly or checks mismatch.
        """
        spec = LstarSpec()
        anchor_block = self._resolved_anchor_block()
        max_slot = self._resolved_max_slot()

        # When the anchor is expected invalid, skip the public_key sync below.
        # That sync would rewrite the state root and mask the inconsistency this path must reject.
        if not self.anchor_valid:
            return self._generate_invalid_anchor(spec, anchor_block, max_slot)

        # The shared key manager caches expensive XMSS keys across tests.
        key_manager = XmssKeyManager.shared(max_slot=max_slot)

        # Test states carry placeholder public keys.
        # Swap in the key manager's real keys or signature verification fails.
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

        # Rewriting validators changes the state root, so the anchor block must follow.
        anchor_state = self.anchor_state.model_copy(
            update={"validators": Validators(data=updated_validators)}
        )
        anchor_block = anchor_block.model_copy(update={"state_root": hash_tree_root(anchor_state)})

        # The store is the node's local chain view, starting from a trusted anchor.
        store = spec.create_store(
            anchor_state,
            anchor_block,
            validator_index=ValidatorIndex(0),
        )

        # Labels let tests reference blocks by name to build forks.
        # The genesis label is always available.
        block_registry: dict[str, Block] = {"genesis": anchor_block}

        # The store is immutable: each spec call returns a new store.
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
                        # Crossing a slot boundary may activate pending attestations.
                        # Always act as aggregator so gossip signatures get aggregated.
                        if step.interval is not None:
                            # An exact interval targets the store's interval clock directly.
                            target_interval = Interval(step.interval)
                        else:
                            assert step.time is not None
                            # A Unix timestamp converts to intervals since genesis.
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
                        # A step expecting the unknown-parent rejection names an unknown parent.
                        # The builder skips the state transition and hands the block to the spec.
                        deliver_unknown_parent = (
                            step.expected_rejection is not None
                            and step.expected_rejection.reason
                            is RejectionReason.UNKNOWN_PARENT_BLOCK
                        )

                        # Fill the lightweight block spec into a complete signed block.
                        signed_block, store = step.block.build_signed_block_with_store(
                            store,
                            block_registry,
                            key_manager,
                            deliver_unknown_parent=deliver_unknown_parent,
                        )
                        filled_block = signed_block.block

                        # Register the label so later blocks can name this one as parent.
                        if step.block.label is not None:
                            if step.block.label in block_registry:
                                raise ValueError(
                                    f"Step {step_index}: duplicate label '{step.block.label}' - "
                                    f"labels must be unique within a test"
                                )
                            block_registry[step.block.label] = filled_block

                        # Advance to the block's slot unless the test delivers it ahead of time.
                        # The tick carries a proposal and acts as aggregator.
                        if step.tick_to_slot:
                            target_interval = Interval.from_slot(filled_block.slot)
                            store, _ = spec.on_tick(
                                store, target_interval, has_proposal=True, is_aggregator=True
                            )

                        # Validate, apply the state transition, and update the head.
                        store = spec.on_block(store, signed_block)

                    case AttestationStep():
                        # Gossip attestations arrive outside blocks and feed the weight calculation.
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

                # Snapshot the canonical store observables clients must reproduce.
                # The authored checks below stay a human-readable overlay.
                store_snapshot = StoreSnapshot.from_store(store)

                if step.checks is not None:
                    step.checks.validate_against_store(
                        store,
                        step_index=step_index,
                        block_registry=block_registry,
                        filled_block=filled_block,
                        old_head=old_head,
                    )

            except (SpecRejectionError, AggregationError) as exception:
                # Steps marked invalid should raise here.
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

                # The rejected call left the store unchanged.
                # Snapshot it anyway so clients verify the no-op.
                store_snapshot = StoreSnapshot.from_store(store)

            else:
                # A step that expected failure but succeeded is a test bug.
                if not step.valid:
                    raise AssertionError(
                        f"Step {step_index} ({type(step).__name__}) succeeded but expected failure"
                    )

            # Emit the filled counterpart, keeping any built payload and the unchanged store.
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
        Assert that store initialization rejects the anchor pair, emitting the reason.

        Raises:
            AssertionError: If initialization succeeds or fails for the wrong reason.
        """
        assert self.steps == [], (
            "steps must be empty when anchor_valid is False: "
            "Store.from_anchor is expected to fail before any step can run"
        )
        # A bare "reject this anchor" vector lets a client reject for the wrong reason and pass.
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
