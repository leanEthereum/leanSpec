"""
Validator service for producing blocks and attestations.

The Validator Problem
---------------------
Ethereum consensus requires active participation from validators.

At specific intervals within each slot, validators must:
- Interval 0: Propose blocks (if scheduled)
- Interval 1: Create attestations (broadcast to subnet topics only)

This service drives validator duties by monitoring the slot clock
and triggering production at the appropriate intervals.

Dual-Key Signing Design
------------------------
Each validator has two XMSS key pairs:

- **Proposal key**: Signs the block root (hash_tree_root(block)) during proposal
- **Attestation key**: Signs gossip attestations for aggregation

Proposers produce two signatures per slot:

1. Interval 0: Proposer signature over the block root (proposal key)
2. Interval 1: Gossip attestation like all other validators (attestation key)

These use independent keys, so OTS constraints do not conflict.
The proposer's attestation is not special — it flows through the normal
gossip/aggregation pipeline and gets included in a future block.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal

from lean_spec.forks import (
    AttestationData,
    AttestationSignatures,
    Block,
    BlockSignatures,
    LstarSpec,
    SignedAttestation,
    SignedBlock,
)
from lean_spec.subspecs.chain.clock import Interval, SlotClock
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync import SyncService
from lean_spec.subspecs.xmss import TARGET_SIGNATURE_SCHEME
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.types import Bytes32, Slot, Uint64, ValidatorIndex

from .constants import HYSTERESIS_BAND, NETWORK_STALL_THRESHOLD, SYNC_LAG_THRESHOLD
from .registry import ValidatorEntry, ValidatorRegistry

logger = logging.getLogger(__name__)

type BlockPublisher = Callable[[SignedBlock], Awaitable[None]]
"""Callback for publishing signed blocks."""
type AttestationPublisher = Callable[[SignedAttestation], Awaitable[None]]
"""Callback for publishing produced attestations."""


async def _noop_block_publisher(block: SignedBlock) -> None:  # noqa: ARG001
    """Default no-op block publisher."""


async def _noop_attestation_publisher(attestation: SignedAttestation) -> None:  # noqa: ARG001
    """Default no-op attestation publisher."""


@dataclass(slots=True)
class ValidatorService:
    """
    Drives validator duties based on the slot clock.

    - Monitors interval boundaries
    - Triggers block production or attestation creation when scheduled
    """

    sync_service: SyncService
    """Service providing access to the forkchoice store."""

    clock: SlotClock
    """Slot clock for time calculation."""

    registry: ValidatorRegistry
    """Registry of validators we control."""

    spec: LstarSpec = field(default_factory=LstarSpec)
    """Fork spec driving consensus methods. Default lets tests skip wiring."""

    on_block: BlockPublisher = field(default=_noop_block_publisher)
    """Callback invoked when a block is produced."""

    on_attestation: AttestationPublisher = field(default=_noop_attestation_publisher)
    """Callback invoked when an attestation is produced."""

    _running: bool = field(default=False, repr=False)
    """Whether the service is running."""

    _blocks_produced: int = field(default=0, repr=False)
    """Counter for produced blocks."""

    _attestations_produced: int = field(default=0, repr=False)
    """Counter for produced attestations."""

    _attested_slots: set[Slot] = field(default_factory=set, repr=False)
    """Slots for which we've already produced attestations (prevents duplicates)."""

    _blocks_skipped_lag: int = field(default=0, repr=False)
    """Block proposals skipped because the local view was too stale."""

    _attestations_skipped_lag: int = field(default=0, repr=False)
    """Attestations skipped because the local view was too stale."""

    _duty_gate_closed: bool = field(default=False, repr=False)
    """Hysteresis flag. True while signing is silenced."""

    async def run(self) -> None:
        """
        Main loop - check duties every interval.

        The loop:
        1. Sleeps until the next interval boundary
        2. Checks current interval within the slot
        3. Triggers appropriate duties
        4. Repeats until stopped

        NOTE: We track the last handled interval to avoid skipping intervals.
        If duty processing takes time and we end up in a new interval, we
        handle that interval immediately instead of sleeping past it.
        """
        self._running = True
        last_handled_total_interval: Interval | None = None

        while self._running:
            # Get current total interval count (not just within-slot).
            total_interval = self.clock.total_intervals()

            # If we've already handled this interval, sleep until the next boundary.
            already_handled = (
                last_handled_total_interval is not None
                and total_interval <= last_handled_total_interval
            )
            if already_handled:
                await self.clock.sleep_until_next_interval()
                total_interval = self.clock.total_intervals()

            # Skip if we have no validators to manage.
            if len(self.registry) == 0:
                last_handled_total_interval = total_interval
                continue

            # Get current slot and interval.
            #
            # Interval determines which duty type to check:
            # - Interval 0: Block production
            # - Interval 1: Attestation production
            slot = self.clock.current_slot()
            interval = self.clock.current_interval()

            my_indices = list(self.registry.indices())
            logger.debug(
                "ValidatorService: slot=%d interval=%d total_interval=%d my_indices=%s",
                slot,
                interval,
                total_interval,
                my_indices,
            )

            if interval == Uint64(0):
                # Block production interval.
                #
                # Check if any of our validators is the proposer.
                logger.debug("ValidatorService: checking block production for slot %d", slot)
                if self._is_synced_for_duties(slot, "block"):
                    await self._maybe_produce_block(slot)
                else:
                    self._blocks_skipped_lag += 1
                logger.debug("ValidatorService: done block production check for slot %d", slot)

                # Re-fetch interval after block production.
                #
                # Block production can take time (signing, network calls, etc.).
                # If we've moved past interval 0, we should check attestation production
                # in this same iteration rather than sleeping and missing it.
                interval = self.clock.current_interval()

            # Attestation check - produce if we haven't attested for this slot yet.
            #
            # Non-proposers attest at interval 1. Proposers bundle their attestation
            # in the block (interval 0). But if we missed interval 1 due to timing,
            # we should still attest as soon as we can within the same slot.
            #
            # We track attested slots to prevent duplicate attestations.
            logger.debug(
                "ValidatorService: attestation check interval=%d slot=%d attested=%s",
                interval,
                slot,
                slot in self._attested_slots,
            )
            # Decide whether this iteration owes an attestation.
            #
            # Two conditions:
            #
            # - Interval has reached the attestation slot (>= 1).
            # - This slot has not already been attested.
            #
            # Why split eligibility from the sync gate: the skip counter
            # must only tick on real misses, never on wrong-interval
            # iterations.
            needs_attestation = interval >= Uint64(1) and slot not in self._attested_slots
            if needs_attestation:
                logger.debug(
                    "ValidatorService: producing attestations for slot %d (interval %d)",
                    slot,
                    interval,
                )
                # Apply the sync gate.
                #
                # Invariant: a gated slot stays out of the attested set.
                # If the node catches up before the slot ends, the next
                # iteration retries the duty.
                if self._is_synced_for_duties(slot, "attestation"):
                    await self._produce_attestations(slot)
                    logger.debug("ValidatorService: done producing attestations for slot %d", slot)
                    self._attested_slots.add(slot)

                    # Prune old entries to bound memory.
                    #
                    # Keep only slots at or after (current slot - 4).
                    # Older slots are no longer attestable.
                    prune_threshold = Slot(max(0, int(slot) - 4))
                    self._attested_slots = {s for s in self._attested_slots if s >= prune_threshold}
                else:
                    self._attestations_skipped_lag += 1

            # Intervals 2-4 have no additional validator duties.

            # Mark this interval as handled.
            #
            # Use the current total interval, not the one from loop start.
            # This prevents re-handling intervals we've already covered.
            last_handled_total_interval = self.clock.total_intervals()
            logger.debug(
                "ValidatorService: end of iteration, last_handled=%d, sleeping...",
                last_handled_total_interval,
            )

    async def _maybe_produce_block(self, slot: Slot) -> None:
        """
        Produce a block if we are the proposer for this slot.

        Checks the proposer schedule against our validator registry.
        If one of our validators should propose, produces and emits the block.

        The proposer signs the block root with the proposal key.
        Attestation happens separately at interval 1 using the attestation key.

        Args:
            slot: Current slot number.
        """
        store = self.sync_service.store
        head_state = store.states.get(store.head)
        if head_state is None:
            logger.debug("Block production: no head state for slot %d", slot)
            return

        num_validators = Uint64(len(head_state.validators))
        if num_validators == Uint64(0):
            logger.debug("Block production: no validators in state for slot %d", slot)
            return

        my_indices = list(self.registry.indices())
        expected_proposer = int(slot) % int(num_validators)
        logger.debug(
            "Block production check: slot=%d num_validators=%d expected_proposer=%d my_indices=%s",
            slot,
            num_validators,
            expected_proposer,
            my_indices,
        )

        # Check each validator we control.
        #
        # Only one validator can be the proposer per slot.
        for validator_index in self.registry.indices():
            if not validator_index.is_proposer_for(slot, num_validators):
                continue

            # We are the proposer for this slot.
            try:
                new_store, block, signatures = self.spec.produce_block_with_signatures(
                    store,
                    slot=slot,
                    validator_index=validator_index,
                )

                # Diagnostic: log parent details so we can verify interop tests.
                parent_block = store.blocks.get(block.parent_root)
                parent_slot = parent_block.slot if parent_block else "UNKNOWN"
                parent_proposer = parent_block.proposer_index if parent_block else "?"
                logger.info(
                    "Produced block slot=%d proposer=%d parent_root=%s "
                    "parent_slot=%s parent_proposer=%s",
                    slot,
                    validator_index,
                    block.parent_root.hex()[:16],
                    parent_slot,
                    parent_proposer,
                )

                self.sync_service.store = new_store

                # Sign the block: proposer_signature covers the block root.
                signed_block = self._sign_block(block, validator_index, signatures)

                self._blocks_produced += 1

                # Emit the block for network propagation.
                await self.on_block(signed_block)

            except AssertionError as e:
                # Proposer validation failed.
                #
                # This can happen during slot boundary transitions.
                # Block production is skipped; attestation still happens at interval 1.
                logger.debug(
                    "Block production skipped for validator %d at slot %d: %s",
                    validator_index,
                    slot,
                    e,
                )

            # Only one proposer per slot.
            break

    async def _produce_attestations(self, slot: Slot) -> None:
        """
        Produce gossip attestations for all validators we control.

        Every validator gossips an attestation signed with the attestation key.
        Proposers also attest here — their block envelope carries a separate
        proposal-key signature, so there is no conflict with OTS constraints.

        Args:
            slot: Current slot number.
        """
        # Wait briefly for the current slot's block to arrive via gossip.
        #
        # At interval 1 (800ms after slot start), the slot's block may not
        # have arrived yet from the proposer node (production + gossip + verification
        # can exceed 800ms on slow machines). Without the block, attestations
        # would reference an old head, causing safe_target to stall.
        store = self.sync_service.store
        current_slot_has_block = any(block.slot == slot for block in store.blocks.values())
        if not current_slot_has_block:
            for _ in range(8):
                await asyncio.sleep(0.05)
                store = self.sync_service.store
                if any(block.slot == slot for block in store.blocks.values()):
                    break

        # Ensure we are attesting to the latest known head
        self.sync_service.store = self.spec.update_head(self.sync_service.store)
        store = self.sync_service.store

        head_state = store.states.get(store.head)
        if head_state is None:
            return

        for validator_index in self.registry.indices():
            attestation_data = self.spec.produce_attestation_data(store, slot)
            signed_attestation = self._sign_attestation(attestation_data, validator_index)

            self._attestations_produced += 1

            # Process attestation locally before publishing.
            #
            # Gossipsub does not deliver messages back to the sender.
            # Without local processing, the aggregator node never sees its own
            # validator's attestation in attestation_signatures, reducing the
            # aggregation count below the 2/3 safe-target threshold.
            is_aggregator_role = (
                self.sync_service.store.validator_id is not None and self.sync_service.is_aggregator
            )
            try:
                self.sync_service.store = self.spec.on_gossip_attestation(
                    self.sync_service.store,
                    signed_attestation=signed_attestation,
                    is_aggregator=is_aggregator_role,
                )
            except Exception:
                # Best-effort: the attestation always goes via gossip regardless.
                logger.debug(
                    "on_gossip_attestation failed for validator %d at slot %d",
                    validator_index,
                    slot,
                    exc_info=True,
                )

            # Emit the attestation for network propagation.
            await self.on_attestation(signed_attestation)

    def _sign_block(
        self,
        block: Block,
        validator_index: ValidatorIndex,
        attestation_signatures: list[AggregatedSignatureProof],
    ) -> SignedBlock:
        """
        Sign a block and wrap it for publishing.

        Signs hash_tree_root(block) with the proposer's proposal key.

        Args:
            block: The block to sign.
            validator_index: Index of the proposing validator.
            attestation_signatures: Aggregated signatures for included attestations.

        Returns:
            Signed block ready for publishing.
        """
        entry = self.registry.get(validator_index)
        if entry is None:
            raise ValueError(f"No secret key for validator {validator_index}")

        # Sign the block root with the proposal key.
        block_root = hash_tree_root(block)
        _, proposer_signature = self._sign_with_key(
            entry,
            block.slot,
            block_root,
            "proposal_secret_key",
        )

        signature = BlockSignatures(
            attestation_signatures=AttestationSignatures(data=attestation_signatures),
            proposer_signature=proposer_signature,
        )

        return SignedBlock(
            block=block,
            signature=signature,
        )

    def _sign_attestation(
        self,
        attestation_data: AttestationData,
        validator_index: ValidatorIndex,
    ) -> SignedAttestation:
        """
        Sign an attestation for publishing.

        Signs the attestation data root with the validator's attestation key.

        Args:
            attestation_data: The attestation data to sign.
            validator_index: Index of the attesting validator.

        Returns:
            Signed attestation ready for publishing.
        """
        # Get the secret key for this validator.
        entry = self.registry.get(validator_index)
        if entry is None:
            raise ValueError(f"No secret key for validator {validator_index}")

        # Sign the attestation data root with the attestation key.
        _, signature = self._sign_with_key(
            entry,
            attestation_data.slot,
            hash_tree_root(attestation_data),
            "attestation_secret_key",
        )

        return SignedAttestation(
            validator_id=validator_index,
            data=attestation_data,
            signature=signature,
        )

    def _sign_with_key(
        self,
        entry: ValidatorEntry,
        slot: Slot,
        message: Bytes32,
        key_field: Literal["attestation_secret_key", "proposal_secret_key"],
    ) -> tuple[ValidatorEntry, Signature]:
        """
        Prepare an XMSS key for the given slot, sign, and update the registry.

        Handles the full lifecycle:

        1. Advance the key until the slot is within its prepared interval
        2. Sign the message
        3. Persist the updated key state in the registry

        Args:
            entry: Validator entry containing the secret keys.
            slot: The slot to sign for.
            message: The message bytes to sign.
            key_field: Which secret key field to use and advance.

        Returns:
            Tuple of (updated entry, signature).
        """
        scheme = TARGET_SIGNATURE_SCHEME
        secret_key = getattr(entry, key_field)

        slot_int = int(slot)
        while slot_int not in scheme.get_prepared_interval(secret_key):
            secret_key = scheme.advance_preparation(secret_key)

        signature = scheme.sign(secret_key, slot, message)

        updated_entry = ValidatorEntry(
            index=entry.index,
            **{
                "attestation_secret_key": entry.attestation_secret_key,
                "proposal_secret_key": entry.proposal_secret_key,
                key_field: secret_key,
            },
        )
        self.registry.add(updated_entry)
        return updated_entry, signature

    def _is_synced_for_duties(
        self,
        slot: Slot,
        duty: Literal["block", "attestation"],
    ) -> bool:
        """Decide whether duties may run for the given slot.

        Combines local lag and local-store stall evidence with
        hysteresis. Returns False only when the local view is stale
        relative to a network that is otherwise making progress.

        Args:
            slot: Wall-clock slot for which a duty would run.
            duty: Tag for the transition log.

        Returns:
            True when duties should run, False to silence them.
        """
        store = self.sync_service.store
        head_block = store.blocks.get(store.head)

        # No head: nothing to compare against, let downstream code no-op.
        if head_block is None:
            return True

        head_slot = head_block.slot

        # Saturate at zero lag when the head is ahead of wall clock.
        #
        # Why:
        #     Local clock drift is normal. Unconditional trust would let
        #     a chain 100 slots in the future bypass every check.
        lag = 0 if head_slot >= slot else int(slot - head_slot)

        # Local stall evidence from the block map.
        #
        # Why:
        #     Only blocks with valid signatures enter the map, so the
        #     freshest entry is an authenticated lower bound on the
        #     network tip. A stale max here means the network is not
        #     producing.
        max_seen_slot = max(
            (b.slot for b in store.blocks.values()),
            default=head_slot,
        )
        network_lag = 0 if max_seen_slot >= slot else int(slot - max_seen_slot)
        network_stalling = network_lag > NETWORK_STALL_THRESHOLD

        # Decision matrix:
        #
        # - Network stalling: keep signing, reopen if currently closed.
        # - Gate closed: reopen only when lag drops to 4 - 2 = 2.
        # - Gate open: close as soon as lag crosses 4.
        if network_stalling:
            allow = True
            if self._duty_gate_closed:
                self._duty_gate_closed = False
                logger.info(
                    "Validator duty gate reopened: network stall detected. "
                    "duty=%s slot=%d head_slot=%d lag=%d max_seen_slot=%d network_lag=%d",
                    duty,
                    int(slot),
                    int(head_slot),
                    lag,
                    int(max_seen_slot),
                    network_lag,
                )
        elif self._duty_gate_closed:
            # Hysteresis: reopen only well below the threshold.
            allow = lag <= SYNC_LAG_THRESHOLD - HYSTERESIS_BAND
            if allow:
                self._duty_gate_closed = False
                logger.info(
                    "Validator duty gate reopened: local view caught up. "
                    "duty=%s slot=%d head_slot=%d lag=%d",
                    duty,
                    int(slot),
                    int(head_slot),
                    lag,
                )
        else:
            # Open gate: close once the local threshold is crossed.
            allow = lag <= SYNC_LAG_THRESHOLD
            if not allow:
                self._duty_gate_closed = True
                logger.info(
                    "Validator duty gate closed: local view is stale. "
                    "duty=%s slot=%d head_slot=%d lag=%d max_seen_slot=%d network_lag=%d",
                    duty,
                    int(slot),
                    int(head_slot),
                    lag,
                    int(max_seen_slot),
                    network_lag,
                )

        return allow

    def stop(self) -> None:
        """
        Stop the service.

        Sets the running flag to False, causing the main loop to exit
        after completing its current sleep cycle.
        """
        self._running = False

    @property
    def is_running(self) -> bool:
        """Check if the service is currently running."""
        return self._running

    @property
    def blocks_produced(self) -> int:
        """Total blocks produced since creation."""
        return self._blocks_produced

    @property
    def attestations_produced(self) -> int:
        """Total attestations produced since creation."""
        return self._attestations_produced

    @property
    def blocks_skipped_lag(self) -> int:
        """Block proposals skipped because the local view was too stale."""
        return self._blocks_skipped_lag

    @property
    def attestations_skipped_lag(self) -> int:
        """Attestations skipped because the local view was too stale."""
        return self._attestations_skipped_lag

    @property
    def duty_gate_closed(self) -> bool:
        """True while the sync-lag gate is silencing duties."""
        return self._duty_gate_closed
