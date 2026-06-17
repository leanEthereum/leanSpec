"""Validator duty execution off the slot clock."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import Final, Literal

from lean_spec.node.chain.clock import SlotClock
from lean_spec.node.sync import SyncService
from lean_spec.node.validator.constants import (
    HYSTERESIS_BAND,
    NETWORK_STALL_THRESHOLD,
    SYNC_LAG_THRESHOLD,
)
from lean_spec.node.validator.registry import ValidatorEntry, ValidatorRegistry
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss import TARGET_SIGNATURE_SCHEME
from lean_spec.spec.crypto.xmss.containers import PublicKey, Signature
from lean_spec.spec.forks import (
    Block,
    Interval,
    LstarSpec,
    SignedAttestation,
    SignedBlock,
    Slot,
    ValidatorIndex,
)
from lean_spec.spec.forks.lstar.containers import MultiMessageAggregate, SingleMessageAggregate
from lean_spec.spec.ssz import Bytes32, Uint64

logger = logging.getLogger(__name__)

type BlockPublisher = Callable[[SignedBlock], Awaitable[None]]
"""Callback for publishing signed blocks."""
type AttestationPublisher = Callable[[SignedAttestation], Awaitable[None]]
"""Callback for publishing produced attestations."""

ATTESTED_SLOT_RETENTION: Final[int] = 4
"""Slots of attestation dedup history to keep; older slots can no longer be attested."""


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
    """Fork spec driving consensus methods."""

    on_block: BlockPublisher | None = field(default=None)
    """Callback to publish a produced block, or None in tests and offline runs."""

    on_attestation: AttestationPublisher | None = field(default=None)
    """Callback to publish a produced attestation, or None in tests and offline runs."""

    _running: bool = field(default=False, repr=False)
    """Whether the service is running."""

    _blocks_produced: int = field(default=0, repr=False)
    """Counter for produced blocks."""

    _attestations_produced: int = field(default=0, repr=False)
    """Counter for produced attestations."""

    _attested_slots: set[Slot] = field(default_factory=set, repr=False)
    """Slots for which we've already produced attestations (prevents duplicates)."""

    _duty_gate_closed: bool = field(default=False, repr=False)
    """Hysteresis flag. True while signing is silenced."""

    async def run(self) -> None:
        """
        Check and run duties once per interval until stopped.

        Track the last handled interval so a slow duty does not skip one.
        If processing spills into a new interval, handle it at once rather than sleeping past it.
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

            # Nothing to do without validators to manage.
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

            if interval == Interval(0):
                if self._is_synced_for_duties(slot, "block"):
                    await self._maybe_produce_block(slot)
                # Block production can outlast interval 0.
                # Re-read so a slow proposal still attests this slot.
                interval = self.clock.current_interval()

            # Attest once per slot. A gated slot stays unattested and retries on a later pass.
            if (
                interval >= Interval(1)
                and slot not in self._attested_slots
                and self._is_synced_for_duties(slot, "attestation")
            ):
                await self._produce_attestations(slot)
                self._attested_slots.add(slot)

                # Drop slots too old to attest again, bounding memory.
                prune_threshold = Slot(max(0, int(slot) - ATTESTED_SLOT_RETENTION))
                self._attested_slots = {
                    attested_slot
                    for attested_slot in self._attested_slots
                    if attested_slot >= prune_threshold
                }

            # Intervals 2-4 have no additional validator duties.

            # Mark this interval as handled.
            #
            # Use the current total interval, not the one from loop start.
            # This prevents re-handling intervals we've already covered.
            last_handled_total_interval = self.clock.total_intervals()

    async def _maybe_produce_block(self, slot: Slot) -> None:
        """Produce and emit a block if one of our validators is this slot's proposer."""
        store = self.sync_service.store
        head_state = store.states.get(store.head)
        if head_state is None:
            logger.debug("Block production: no head state for slot %d", slot)
            return

        num_validators = Uint64(len(head_state.validators))
        if num_validators == Uint64(0):
            logger.debug("Block production: no validators in state for slot %d", slot)
            return

        # Only one validator proposes per slot; act only if it is one of ours.
        expected_proposer = ValidatorIndex.proposer_for_slot(slot, num_validators)
        logger.debug(
            "Block production check: slot=%d num_validators=%d expected_proposer=%d my_indices=%s",
            slot,
            num_validators,
            expected_proposer,
            list(self.registry.indices()),
        )
        if expected_proposer not in self.registry:
            return
        validator_index = expected_proposer

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

            # Sign the block root, then merge that signature with the attestation proofs.
            signed_block = self._sign_block(block, validator_index, signatures)

            self._blocks_produced += 1

            if self.on_block is not None:
                await self.on_block(signed_block)

        except AssertionError as exception:
            # Slot-boundary races can fail proposer validation.
            # Skip block production; the attestation at interval 1 still happens.
            logger.debug(
                "Block production skipped for validator %d at slot %d: %s",
                validator_index,
                slot,
                exception,
            )

    async def _produce_attestations(self, slot: Slot) -> None:
        """Produce and gossip an attestation for every validator we control."""
        # Wait briefly for this slot's block before attesting.
        #
        # Production and gossip can exceed interval 1 on slow machines.
        #
        # Without it, attestations reference an old head and stall the safe target.
        store = self.sync_service.store
        current_slot_has_block = any(block.slot == slot for block in store.blocks.values())
        if not current_slot_has_block:
            for _ in range(8):
                await asyncio.sleep(0.05)
                store = self.sync_service.store
                if any(block.slot == slot for block in store.blocks.values()):
                    break

        # Attest to the latest known head.
        self.sync_service.store = self.spec.update_head(self.sync_service.store)
        store = self.sync_service.store

        head_state = store.states.get(store.head)
        if head_state is None:
            return

        for validator_index in self.registry.indices():
            validator_entry = self.registry.get(validator_index)
            if validator_entry is None:
                raise ValueError(f"No secret key for validator {validator_index}")

            attestation_data = self.spec.produce_attestation_data(store, slot)
            signed_attestation = SignedAttestation(
                validator_index=validator_index,
                data=attestation_data,
                signature=self._sign_with_key(
                    validator_entry,
                    attestation_data.slot,
                    hash_tree_root(attestation_data),
                    "attestation_secret_key",
                ),
            )

            self._attestations_produced += 1

            # Process locally before publishing: gossip does not echo to the sender.
            # Otherwise an aggregator never counts its own validator's attestation,
            # dropping the aggregation below the 2/3 safe-target threshold.
            is_aggregator_role = (
                self.sync_service.store.validator_index is not None
                and self.sync_service.is_aggregator
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

            if self.on_attestation is not None:
                await self.on_attestation(signed_attestation)

    def _sign_block(
        self,
        block: Block,
        validator_index: ValidatorIndex,
        attestation_proofs: list[SingleMessageAggregate],
    ) -> SignedBlock:
        """
        Sign a block and wrap it with its merged proof for publishing.

        The proposer signature and the attestation proofs merge into one block proof.
        The attestation proofs run parallel to the block body's attestations.
        """
        validator_entry = self.registry.get(validator_index)
        if validator_entry is None:
            raise ValueError(f"No secret key for validator {validator_index}")

        # Sign the block root with the proposal key.
        block_root = hash_tree_root(block)
        proposer_signature = self._sign_with_key(
            validator_entry,
            block.slot,
            block_root,
            "proposal_secret_key",
        )

        # Resolve validator public_keys from state using validator indices.
        key_state = self.sync_service.store.states.get(block_root)
        if key_state is None:
            key_state = self.sync_service.store.states.get(self.sync_service.store.head)
        if key_state is None:
            raise ValueError(
                "No state available to resolve validator public keys for block signing"
            )

        validators = key_state.validators
        if not validator_index.is_within_registry(Uint64(len(validators))):
            raise ValueError(f"Validator {validator_index} not found in state validators")
        proposer_public_key = PublicKey.decode_bytes(
            validators[validator_index].proposal_public_key
        )

        # Wrap the proposer's raw XMSS signature into a singleton single-message aggregate.
        # The single fresh entry carries the proposer index alongside its key and signature.
        proposer_single_message_aggregate = SingleMessageAggregate.aggregate(
            children=[],
            raw_xmss=[(validator_index, proposer_public_key, proposer_signature)],
            message=block_root,
            slot=block.slot,
        )

        # Collect the public keys for each proof, in the same order as the proofs.
        num_validators = Uint64(len(validators))
        public_keys_per_aggregate: list[list[PublicKey]] = []
        for attestation_proof in attestation_proofs:
            participant_public_keys: list[PublicKey] = []
            for validator_index in attestation_proof.participants.to_validator_indices():
                # Every participant must index the active validator set.
                # A stale entry would otherwise fail deep inside the aggregator.
                if not validator_index.is_within_registry(num_validators):
                    raise ValueError(
                        f"Attestation proof references validator {validator_index}; "
                        f"active set has {num_validators} validators"
                    )
                participant_public_keys.append(
                    PublicKey.decode_bytes(validators[validator_index].attestation_public_key)
                )
            public_keys_per_aggregate.append(participant_public_keys)

        # The proposer goes last, parallel to the proposer aggregate appended below.
        public_keys_per_aggregate.append([proposer_public_key])

        merged_block_proof = MultiMessageAggregate.aggregate(
            [*attestation_proofs, proposer_single_message_aggregate],
            public_keys_per_aggregate=public_keys_per_aggregate,
        )

        return SignedBlock(
            block=block,
            proof=merged_block_proof,
        )

    def _sign_with_key(
        self,
        validator_entry: ValidatorEntry,
        slot: Slot,
        message: Bytes32,
        key_field: Literal["attestation_secret_key", "proposal_secret_key"],
    ) -> Signature:
        """
        Advance the chosen XMSS key to the slot, sign, and persist the advanced key.

        XMSS keys are stateful one-time signatures, so each signature consumes key state.
        The advanced key is written back so the next slot does not reuse it.
        """
        scheme = TARGET_SIGNATURE_SCHEME
        secret_key = getattr(validator_entry, key_field)

        slot_int = int(slot)
        while slot_int not in scheme.get_prepared_interval(secret_key):
            secret_key = scheme.advance_preparation(secret_key)

        signature = scheme.sign(secret_key, slot, message)

        # Carry over both secret keys, replacing only the one that was advanced.
        self.registry.add(replace(validator_entry, **{key_field: secret_key}))
        return signature

    def _is_synced_for_duties(
        self,
        slot: Slot,
        duty: Literal["block", "attestation"],
    ) -> bool:
        """
        Decide whether duties may run for this slot.

        Weighs local lag against local-store stall evidence, with hysteresis.
        Returns False only when the local view is stale while the network still progresses.
        The duty argument only labels the transition log.
        """
        store = self.sync_service.store
        head_block = store.blocks.get(store.head)

        # No head: nothing to compare against, let downstream code no-op.
        if head_block is None:
            return True

        head_slot = head_block.slot

        # Saturate at zero lag when the head is ahead of wall clock.
        #
        # Local clock drift is normal.
        # Unconditional trust would let a chain 100 slots in the future bypass every check.
        lag = 0 if head_slot >= slot else int(slot - head_slot)

        # Local stall evidence from the block map.
        #
        # Only blocks with valid signatures enter the map.
        # So the freshest entry is an authenticated lower bound on the network tip.
        # A stale max here means the network is not producing.
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
        """Signal the run loop to exit after its current sleep cycle."""
        self._running = False

    @property
    def is_running(self) -> bool:
        """Whether the service is currently running."""
        return self._running

    @property
    def blocks_produced(self) -> int:
        """Total blocks produced since creation."""
        return self._blocks_produced

    @property
    def attestations_produced(self) -> int:
        """Total attestations produced since creation."""
        return self._attestations_produced
