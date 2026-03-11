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

Dual-Key Attestation Design
----------------------------
Each validator has two XMSS key pairs:

- **Proposal key**: Signs the proposer signature while proposing a block
- **Attestation key**: Signs gossip attestations for aggregation

Proposers produce two attestations per slot:

1. Interval 0: Proposer signature inside the block (proposal key)
2. Interval 1: Gossip attestation like all other validators (attestation key)

These use independent keys, so OTS constraints do not conflict.
The block envelope attestation is added directly to Store.attestation_signatures,
flowing through the normal aggregation pipeline alongside gossip attestations.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from lean_spec.subspecs.chain.clock import Interval, SlotClock
from lean_spec.subspecs.containers import (
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
from lean_spec.subspecs.forkchoice.store import AttestationSignatureEntry
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import Uint64

from .registry import ValidatorEntry, ValidatorRegistry

if TYPE_CHECKING:
    from lean_spec.subspecs.sync import SyncService

logger = logging.getLogger(__name__)

type BlockPublisher = Callable[[SignedBlockWithAttestation], Awaitable[None]]
"""Callback for publishing signed blocks with proposer attestations."""
type AttestationPublisher = Callable[[SignedAttestation], Awaitable[None]]
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

    _attested_slots: set[Slot] = field(default_factory=set, repr=False)
    """Slots for which we've already produced attestations (prevents duplicates)."""

    _cached_signed_attestations: dict[tuple[ValidatorIndex, Slot], SignedAttestation] = field(
        default_factory=dict, repr=False
    )
    """
    Cache of signed proposer attestations keyed by (validator, slot) so the same
    attestation signature can be reused during the gossip step.
    """

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
            logger.debug(
                "ValidatorService: attestation check interval=%d slot=%d attested=%s",
                interval,
                slot,
                slot in self._attested_slots,
            )
            if interval >= Uint64(1) and slot not in self._attested_slots:
                logger.debug(
                    "ValidatorService: producing attestations for slot %d (interval %d)",
                    slot,
                    interval,
                )
                await self._produce_attestations(slot)
                logger.debug("ValidatorService: done producing attestations for slot %d", slot)
                self._attested_slots.add(slot)

                # Prune old entries to prevent unbounded growth.
                #
                # Keep only recent slots (current slot - 4) to bound memory usage.
                # We never need to attest for slots that far in the past.
                prune_threshold = Slot(max(0, int(slot) - 4))
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

        num_validators = Uint64(len(head_state.validators))
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

                # Diagnostic: log parent details so we can verify interop.
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

                # Update the store through sync service.
                #
                # This ensures the block is integrated into forkchoice.
                self.sync_service.store = new_store

                # Create signed block wrapper for publishing.
                #
                # This adds our attestation and signatures to the block.
                signed_block = self._sign_block(block, validator_index, signatures)

                # Add the proposer's attestation signature to the store so our
                # local view matches what other nodes derive when processing the block.
                proposer_att = signed_block.message.proposer_attestation
                store = self.sync_service.store
                att_sigs = {k: set(v) for k, v in store.attestation_signatures.items()}
                att_sigs.setdefault(proposer_att.data, set()).add(
                    AttestationSignatureEntry(proposer_att.validator_id, proposer_att.signature)
                )
                self.sync_service.store = store.model_copy(
                    update={"attestation_signatures": att_sigs}
                )

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
        self.sync_service.store = self.sync_service.store.update_head()
        store = self.sync_service.store

        head_state = store.states.get(store.head)
        if head_state is None:
            return

        for validator_index in self.registry.indices():
            cache_key = (validator_index, slot)
            signed_attestation = self._cached_signed_attestations.pop(cache_key, None)
            if signed_attestation is None:
                # Produce attestation data using Store's method.
                #
                # This calculates head, target, and source checkpoints.
                attestation_data = store.produce_attestation_data(slot)

                # Sign the attestation using our secret key.
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
        # Force the store view to treat the newly built block as head so the
        # attestation votes for the block we are proposing.
        block_root = hash_tree_root(block)
        store_updates: dict[str, object] = {"head": block_root}
        if block_root not in self.sync_service.store.blocks:
            # When blocks are signed in tests they may not exist in the store yet.
            store_updates["blocks"] = self.sync_service.store.blocks | {block_root: block}
        attestation_store = self.sync_service.store.model_copy(update=store_updates)
        proposer_attestation_data = attestation_store.produce_attestation_data(block.slot)
        proposer_attestation = self._sign_attestation(
            attestation_data=proposer_attestation_data,
            validator_index=validator_index,
        )

        # Sign the proposer's attestation.
        #
        # Uses the proposal key, separate from the attestation key.
        # This allows the proposer to also sign a regular attestation at the same slot.
        entry = self.registry.get(validator_index)
        if entry is None:
            raise ValueError(f"No secret key for validator {validator_index}")

        # Ensure the proposal key is prepared for this slot.
        entry = self._ensure_proposal_key_prepared(entry, block.slot)

        proposer_signature = TARGET_SIGNATURE_SCHEME.sign(
            entry.proposal_secret_key,
            block.slot,
            proposer_attestation_data.data_root_bytes(),
        )

        # Cache the signed attestation for reuse during gossip.
        self._cached_signed_attestations[(validator_index, block.slot)] = proposer_attestation

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

        # Ensure the attestation key is prepared for this slot.
        entry = self._ensure_attestation_key_prepared(entry, attestation_data.slot)

        # Sign the attestation data root.
        #
        # Uses the attestation key, separate from the proposal key.
        signature = TARGET_SIGNATURE_SCHEME.sign(
            entry.attestation_secret_key,
            attestation_data.slot,
            attestation_data.data_root_bytes(),
        )

        return SignedAttestation(
            validator_id=validator_index,
            data=attestation_data,
            signature=signature,
        )

    def _ensure_attestation_key_prepared(
        self,
        entry: ValidatorEntry,
        slot: Slot,
    ) -> ValidatorEntry:
        """
        Ensure the attestation secret key is prepared for signing at the given slot.

        XMSS uses a sliding window of prepared slots. If the requested slot
        is outside this window, we advance the preparation by computing
        additional bottom trees until the slot is covered.

        Args:
            entry: Validator entry containing the secret keys.
            slot: The slot at which we need to sign.

        Returns:
            The entry, possibly with an updated attestation secret key.
        """
        scheme = cast(GeneralizedXmssScheme, TARGET_SIGNATURE_SCHEME)
        prepared_interval = scheme.get_prepared_interval(entry.attestation_secret_key)

        slot_int = int(slot)
        if slot_int in prepared_interval:
            return entry

        secret_key = entry.attestation_secret_key
        while slot_int not in scheme.get_prepared_interval(secret_key):
            secret_key = scheme.advance_preparation(secret_key)

        updated_entry = ValidatorEntry(
            index=entry.index,
            attestation_secret_key=secret_key,
            proposal_secret_key=entry.proposal_secret_key,
        )
        self.registry.add(updated_entry)
        return updated_entry

    def _ensure_proposal_key_prepared(
        self,
        entry: ValidatorEntry,
        slot: Slot,
    ) -> ValidatorEntry:
        """
        Ensure the proposal secret key is prepared for signing at the given slot.

        Args:
            entry: Validator entry containing the secret keys.
            slot: The slot at which we need to sign.

        Returns:
            The entry, possibly with an updated proposal secret key.
        """
        scheme = cast(GeneralizedXmssScheme, TARGET_SIGNATURE_SCHEME)
        prepared_interval = scheme.get_prepared_interval(entry.proposal_secret_key)

        slot_int = int(slot)
        if slot_int in prepared_interval:
            return entry

        secret_key = entry.proposal_secret_key
        while slot_int not in scheme.get_prepared_interval(secret_key):
            secret_key = scheme.advance_preparation(secret_key)

        updated_entry = ValidatorEntry(
            index=entry.index,
            attestation_secret_key=entry.attestation_secret_key,
            proposal_secret_key=secret_key,
        )
        self.registry.add(updated_entry)
        return updated_entry

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
