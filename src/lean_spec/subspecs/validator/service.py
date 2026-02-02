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
from typing import TYPE_CHECKING

from lean_spec.subspecs import metrics
from lean_spec.subspecs.chain.clock import Interval, SlotClock
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
from lean_spec.subspecs.xmss import TARGET_SIGNATURE_SCHEME
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import Uint64

from .registry import ValidatorRegistry

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

            if interval == Uint64(0):
                # Block production interval.
                #
                # Check if any of our validators is the proposer.
                await self._maybe_produce_block(slot)

            elif interval == Uint64(1):
                # Attestation interval.
                #
                # All validators should attest to current head.
                await self._produce_attestations(slot)

            # Intervals 2-4 have no validator duties.

            # Mark this interval as handled.
            last_handled_total_interval = total_interval

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
            return

        num_validators = len(head_state.validators)

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

                # The proposer's attestation is already stored in the block.
                # When the block is broadcast, the proposer signature is tracked
                # in gossip_signatures for future aggregation.
                # No need to separately process the proposer attestation.

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
