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

Proposer Attestation Design
---------------------------
Each validator attests exactly once per slot.

However, proposers and non-proposers attest at different times:
- Proposers attest at interval 0, bundled inside their block
- Non-proposers attest at interval 1, broadcast separately

This design has two benefits:
1. Proposers see their own attestation immediately (no network delay)
2. Non-proposers can attest to a block they actually received

The proposer's attestation is embedded in a block wrapper alongside
the block itself. At interval 1, we skip proposers because they already
attested. This prevents double-attestation.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from lean_spec.subspecs import metrics
from lean_spec.subspecs.chain.clock import Interval, SlotClock
from lean_spec.subspecs.chain.config import ATTESTATION_COMMITTEE_COUNT
from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Block,
    SignedAttestation,
    SignedBlockWithAttestation,
    ValidatorIndex,
)
from lean_spec.subspecs.containers.block import (
    AttestationSignatures,
    BlockSignatures,
    BlockWithAttestation,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.xmss import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof, SignatureKey
from lean_spec.types import Uint64

from .registry import ValidatorEntry, ValidatorRegistry

if TYPE_CHECKING:
    from lean_spec.subspecs.sync import SyncService

logger = logging.getLogger(__name__)

BlockPublisher = Callable[[SignedBlockWithAttestation], Awaitable[None]]
"""Callback for publishing signed blocks with proposer attestations."""
AttestationPublisher = Callable[[SignedAttestation], Awaitable[None]]
"""Callback for publishing produced attestations."""


async def _noop_block_publisher(block: SignedBlockWithAttestation) -> None:  # noqa: ARG001
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

    _attested_slots: set[int] = field(default_factory=set, repr=False)
    """Slots for which we've already produced attestations (prevents duplicates)."""

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
                await self._sleep_until_next_interval()
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
                await self._maybe_produce_block(slot)
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
            slot_int = int(slot)
            logger.debug(
                "ValidatorService: attestation check interval=%d slot_int=%d attested=%s",
                interval,
                slot_int,
                slot_int in self._attested_slots,
            )
            if interval >= Uint64(1) and slot_int not in self._attested_slots:
                logger.debug(
                    "ValidatorService: producing attestations for slot %d (interval %d)",
                    slot,
                    interval,
                )
                await self._produce_attestations(slot)
                logger.debug("ValidatorService: done producing attestations for slot %d", slot)
                self._attested_slots.add(slot_int)

                # Prune old entries to prevent unbounded growth.
                #
                # Keep only recent slots (current slot - 4) to bound memory usage.
                # We never need to attest for slots that far in the past.
                prune_threshold = max(0, slot_int - 4)
                self._attested_slots = {s for s in self._attested_slots if s >= prune_threshold}

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

        The proposer's attestation is bundled into the block rather than
        broadcast separately at interval 1. This ensures the proposer's vote
        is included without network round-trip delays.

        Args:
            slot: Current slot number.
        """
        store = self.sync_service.store
        head_state = store.states.get(store.head)
        if head_state is None:
            logger.debug("Block production: no head state for slot %d", slot)
            return

        num_validators = len(head_state.validators)
        my_indices = list(self.registry.indices())
        expected_proposer = int(slot) % num_validators
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
            #
            # Block production includes two steps:
            # 1. Create the block with aggregated attestations from the pool
            # 2. Sign and bundle our own attestation into a block with attestation
            #
            # Our attestation goes in the block envelope, not the body.
            # This separates "attestations we're including" from "our own vote".
            try:
                new_store, block, signatures = store.produce_block_with_signatures(
                    slot=slot,
                    validator_index=validator_index,
                )

                # Update the store through sync service.
                #
                # This ensures the block is integrated into forkchoice.
                self.sync_service.store = new_store

                # Create signed block wrapper for publishing.
                #
                # This adds our attestation and signatures to the block.
                signed_block = self._sign_block(block, validator_index, signatures)

                # Store proposer's attestation signature locally for aggregation.
                #
                # The proposer's block is already in the store from produce_block_with_signatures.
                # When on_gossip_block is called locally, it returns early (duplicate check).
                # So the proposer's attestation signature never reaches gossip_signatures
                # via on_block. We must store it explicitly here so the aggregator
                # (which may be this same node) can include it in aggregation.
                self._store_proposer_attestation_signature(signed_block, validator_index)

                self._blocks_produced += 1
                metrics.blocks_proposed.inc()

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
        Produce attestations for all non-proposer validators we control.

        Every validator attests exactly once per slot. Since proposers already
        bundled their attestation inside the block at interval 0, they are
        skipped here to prevent double-attestation.

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
        self.sync_service.store = self.sync_service.store.update_head()
        store = self.sync_service.store

        head_state = store.states.get(store.head)
        if head_state is None:
            return

        num_validators = len(head_state.validators)

        for validator_index in self.registry.indices():
            # Skip proposer - they already attested within their block.
            #
            # The proposer signed and bundled their attestation at interval 0.
            # Creating another attestation here would violate the
            # "one attestation per validator per slot" invariant.
            if validator_index.is_proposer_for(slot, num_validators):
                continue

            # Produce attestation data using Store's method.
            #
            # This calculates head, target, and source checkpoints.
            attestation_data = store.produce_attestation_data(slot)

            # Sign the attestation using our secret key.
            signed_attestation = self._sign_attestation(attestation_data, validator_index)

            self._attestations_produced += 1
            metrics.attestations_produced.inc()

            # Process attestation locally before publishing.
            #
            # Gossipsub does not deliver messages back to the sender.
            # Without local processing, the aggregator node never sees its own
            # validator's attestation in gossip_signatures, reducing the
            # aggregation count below the 2/3 safe-target threshold.
            is_aggregator_role = (
                self.sync_service.store.validator_id is not None and self.sync_service.is_aggregator
            )
            try:
                self.sync_service.store = self.sync_service.store.on_gossip_attestation(
                    signed_attestation=signed_attestation,
                    is_aggregator=is_aggregator_role,
                )
            except Exception:
                # Best-effort: the attestation always goes via gossip regardless.
                pass

            # Emit the attestation for network propagation.
            await self.on_attestation(signed_attestation)

    def _sign_block(
        self,
        block: Block,
        validator_index: ValidatorIndex,
        attestation_signatures: list[AggregatedSignatureProof],
    ) -> SignedBlockWithAttestation:
        """
        Sign a block and wrap it for publishing.

        Creates the proposer attestation, signs it, and wraps everything
        in a signed block wrapper.

        Args:
            block: The block to sign.
            validator_index: Index of the proposing validator.
            attestation_signatures: Aggregated signatures for included attestations.

        Returns:
            Signed block ready for publishing.
        """
        # Create the proposer's attestation for this slot.
        #
        # The proposer also attests to the chain head they see.
        proposer_attestation_data = self.sync_service.store.produce_attestation_data(block.slot)
        proposer_attestation = Attestation(
            validator_id=validator_index,
            data=proposer_attestation_data,
        )

        # Sign the proposer's attestation.
        #
        # Uses XMSS signature scheme from the validator's secret key.
        entry = self.registry.get(validator_index)
        if entry is None:
            raise ValueError(f"No secret key for validator {validator_index}")

        # Ensure the XMSS secret key is prepared for this epoch.
        entry = self._ensure_prepared_for_epoch(entry, block.slot)

        proposer_signature = TARGET_SIGNATURE_SCHEME.sign(
            entry.secret_key,
            block.slot,
            proposer_attestation_data.data_root_bytes(),
        )

        # Create the message wrapper.
        #
        # Bundles the block with the proposer's attestation.
        message = BlockWithAttestation(
            block=block,
            proposer_attestation=proposer_attestation,
        )

        # Create the signature payload.
        #
        # Contains signatures for all included attestations plus the proposer's.
        signature = BlockSignatures(
            attestation_signatures=AttestationSignatures(data=attestation_signatures),
            proposer_signature=proposer_signature,
        )

        return SignedBlockWithAttestation(
            message=message,
            signature=signature,
        )

    def _sign_attestation(
        self,
        attestation_data: AttestationData,
        validator_index: ValidatorIndex,
    ) -> SignedAttestation:
        """
        Sign an attestation for publishing.

        Uses XMSS signature scheme with the validator's secret key.

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

        # Ensure the XMSS secret key is prepared for this epoch.
        entry = self._ensure_prepared_for_epoch(entry, attestation_data.slot)

        # Sign the attestation data root.
        #
        # Uses XMSS one-time signature for the current epoch (slot).
        signature = TARGET_SIGNATURE_SCHEME.sign(
            entry.secret_key,
            attestation_data.slot,
            attestation_data.data_root_bytes(),
        )

        return SignedAttestation(
            validator_id=validator_index,
            message=attestation_data,
            signature=signature,
        )

    def _store_proposer_attestation_signature(
        self,
        signed_block: SignedBlockWithAttestation,
        validator_index: ValidatorIndex,
    ) -> None:
        """
        Store the proposer's attestation signature in gossip_signatures.

        When the proposer produces a block, the block is added to the store
        immediately. The subsequent local on_gossip_block call returns early
        because the block is already in the store (duplicate check). This means
        the proposer's attestation signature never reaches gossip_signatures
        via the normal on_block path.

        This method explicitly stores the signature so aggregation can include it.

        Args:
            signed_block: The signed block containing the proposer attestation.
            validator_index: The proposer's validator index.
        """
        store = self.sync_service.store
        if store.validator_id is None:
            return

        # Only store if the proposer is in the same subnet as the aggregator.
        proposer_subnet = validator_index.compute_subnet_id(ATTESTATION_COMMITTEE_COUNT)
        current_subnet = store.validator_id.compute_subnet_id(ATTESTATION_COMMITTEE_COUNT)
        if proposer_subnet != current_subnet:
            return

        proposer_attestation = signed_block.message.proposer_attestation
        proposer_signature = signed_block.signature.proposer_signature
        data_root = proposer_attestation.data.data_root_bytes()

        sig_key = SignatureKey(validator_index, data_root)
        new_gossip_sigs = dict(store.gossip_signatures)
        new_gossip_sigs[sig_key] = proposer_signature

        # Also store the attestation data for later extraction during aggregation.
        new_attestation_data_by_root = dict(store.attestation_data_by_root)
        new_attestation_data_by_root[data_root] = proposer_attestation.data

        self.sync_service.store = store.model_copy(
            update={
                "gossip_signatures": new_gossip_sigs,
                "attestation_data_by_root": new_attestation_data_by_root,
            }
        )

    def _ensure_prepared_for_epoch(
        self,
        entry: ValidatorEntry,
        epoch: Slot,
    ) -> ValidatorEntry:
        """
        Ensure the secret key is prepared for signing at the given epoch.

        XMSS uses a sliding window of prepared epochs. If the requested epoch
        is outside this window, we advance the preparation by computing
        additional bottom trees until the epoch is covered.

        Args:
            entry: Validator entry containing the secret key.
            epoch: The epoch (slot) at which we need to sign.

        Returns:
            The entry, possibly with an updated secret key.
        """
        scheme = cast(GeneralizedXmssScheme, TARGET_SIGNATURE_SCHEME)
        get_prepared_interval = scheme.get_prepared_interval(entry.secret_key)

        # If epoch is already in the prepared interval, no action needed.
        epoch_int = int(epoch)
        if epoch_int in get_prepared_interval:
            return entry

        # Advance preparation until the epoch is covered.
        secret_key = entry.secret_key
        while epoch_int not in scheme.get_prepared_interval(secret_key):
            secret_key = scheme.advance_preparation(secret_key)

        # Update the registry with the new secret key.
        updated_entry = ValidatorEntry(
            index=entry.index,
            secret_key=secret_key,
        )
        self.registry.add(updated_entry)

        return updated_entry

    async def _sleep_until_next_interval(self) -> None:
        """
        Sleep until the next interval boundary.

        Uses the clock to calculate precise sleep duration.
        """
        sleep_time = self.clock.seconds_until_next_interval()
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)

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
