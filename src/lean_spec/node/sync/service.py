"""
Sync service orchestrator.

Drives a node from cold start to active participation in the network.
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field

from lean_spec.node.chain.clock import SlotClock
from lean_spec.node.metrics import registry as metrics
from lean_spec.node.networking.reqresp.message import Status
from lean_spec.node.networking.transport.peer_id import PeerId
from lean_spec.node.storage import Database
from lean_spec.node.sync.backfill_sync import BackfillSync, NetworkRequester
from lean_spec.node.sync.block_cache import BlockCache
from lean_spec.node.sync.config import MAX_PENDING_ATTESTATIONS
from lean_spec.node.sync.head_sync import HeadSync
from lean_spec.node.sync.peer_manager import PeerManager
from lean_spec.node.sync.states import SyncState
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.containers import PublicKey
from lean_spec.spec.forks import (
    AttestationData,
    Block,
    LstarSpec,
    RejectionReason,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    Slot,
    SpecRejectionError,
    Store,
)
from lean_spec.spec.forks.lstar.containers import (
    AggregationError,
    SingleMessageAggregate,
)
from lean_spec.spec.ssz import Bytes32

logger = logging.getLogger(__name__)


class UnknownAttestationBlockError(Exception):
    """An attestation references a source, target, or head block the store has not seen yet."""


BUFFERABLE_REJECTION_REASONS: frozenset[RejectionReason] = frozenset(
    {
        RejectionReason.UNKNOWN_SOURCE_BLOCK,
        RejectionReason.UNKNOWN_TARGET_BLOCK,
        RejectionReason.UNKNOWN_HEAD_BLOCK,
    }
)
"""Rejections a later block can resolve, so the attestation is worth replaying."""


@dataclass(slots=True)
class SyncService:
    """Central coordinator for the sync state machine."""

    store: Store
    """Current forkchoice store. Updated as blocks are processed."""

    peer_manager: PeerManager
    """Peer manager for selection."""

    block_cache: BlockCache
    """Block cache for pending blocks."""

    clock: SlotClock
    """Slot clock for time conversion."""

    network: NetworkRequester
    """Network interface for block requests."""

    spec: LstarSpec = field(default_factory=LstarSpec)
    """Fork spec driving consensus methods. Default lets tests skip wiring."""

    database: Database | None = field(default=None)
    """Optional database for persisting blocks and states."""

    is_aggregator: bool = field(default=False)
    """Whether this node functions as an aggregator."""

    publish_aggregated_attestation: (
        Callable[[SignedAggregatedAttestation], Coroutine[None, None, None]] | None
    ) = field(default=None)
    """Async callback for publishing aggregated attestations, or None when no publisher is wired."""

    state: SyncState = field(default=SyncState.IDLE)
    """Current sync state. Defaults to IDLE, awaiting peer status."""

    genesis_start: bool = field(default=False)
    """When True, start in SYNCING state to accept gossip without waiting for peers."""

    _backfill: BackfillSync | None = field(default=None)
    """Backfill syncer instance (created lazily)."""

    _head_sync: HeadSync | None = field(default=None)
    """Head syncer instance (created lazily)."""

    _blocks_processed: int = field(default=0)
    """Counter for processed blocks."""

    _pending_attestations: deque[SignedAttestation] = field(
        default_factory=lambda: deque(maxlen=MAX_PENDING_ATTESTATIONS)
    )
    """
    Attestations queued for replay after the next block lands.

    An attestation referencing a not-yet-received block fails validation.

    Buffering avoids dropping votes that arrived slightly out of order.

    Bounded so overflow drops the oldest entry first.
    """

    _pending_aggregated_attestations: deque[SignedAggregatedAttestation] = field(
        default_factory=lambda: deque(maxlen=MAX_PENDING_ATTESTATIONS)
    )
    """
    Aggregated attestations awaiting block processing.

    Same buffering strategy as individual attestations.
    """

    _pending_block_aggregates: list[SignedAggregatedAttestation] = field(default_factory=list)
    """Aggregates recovered from processed blocks, queued for the aggregator to publish."""

    def __post_init__(self) -> None:
        """Wire sub-components and apply the genesis-start state hint."""
        # Backfill reads the store through self, so it sees each post-block reassignment.
        self._backfill = BackfillSync(
            peer_manager=self.peer_manager,
            block_cache=self.block_cache,
            network=self.network,
            store_view=self,
        )
        self._head_sync = HeadSync(
            block_cache=self.block_cache,
            backfill=self._backfill,
            process_block=self.process_block,
        )

        # Genesis validators already hold the full genesis state.
        # They process gossip blocks immediately without a peer status exchange.
        if self.genesis_start:
            self.state = SyncState.SYNCING

    def process_block(self, store: Store, block: SignedBlock) -> Store:
        """Apply a block to the store, emit telemetry, and persist when wired up."""
        new_store = self.spec.on_block(store, block)

        # Live chain pointers, exposed as gauges so dashboards reflect the current view.
        metrics.lean_head_slot.set(new_store.blocks[new_store.head].slot)
        metrics.lean_safe_target_slot.set(new_store.blocks[new_store.safe_target].slot)
        metrics.lean_latest_justified_slot.set(new_store.latest_justified.slot)
        metrics.lean_latest_finalized_slot.set(new_store.latest_finalized.slot)

        # A head change means forkchoice picked a different canonical tip.
        # - A simple chain extension produces depth 0;
        # - A true reorg produces depth > 0.
        if new_store.head != store.head:
            # Walk parent links from a starting root until we leave the store.
            # Termination: the walk ends at the first parent link missing from the store.
            #
            # Example: store holds G (genesis, parent = 0), A (parent G), B (parent A).
            #
            #   ancestors(B):
            #     root=B   parent=A   seen={B}        -> root=A
            #     root=A   parent=G   seen={B,A}      -> root=G
            #     root=G   parent=0   seen={B,A,G}    -> root=0
            #     root=0   blocks.get returns None    -> stop
            #
            #   returns {B, A, G}
            def ancestors(start: Bytes32) -> set[Bytes32]:
                seen: set[Bytes32] = set()
                root = start
                while (block := new_store.blocks.get(root)) is not None:
                    seen.add(root)
                    root = block.parent_root
                return seen

            # Reorg depth = blocks that lived on the old chain but not on the new one.
            #
            # The two chains share a common ancestor; everything at or below it cancels:
            #
            #     G --- A --- B --- C        ancestors(C) = {G, A, B, C}
            #                 \
            #                  X --- Y       ancestors(Y) = {G, A, X, Y}
            #
            #     ancestors(C) - ancestors(Y) = {B, C}     -> depth = 2
            depth = len(ancestors(store.head) - ancestors(new_store.head))
            metrics.lean_fork_choice_reorgs_total.inc()
            metrics.lean_fork_choice_reorg_depth.observe(depth)

        # Track processed blocks.
        #
        # We only count blocks that pass validation and update the store.
        self._blocks_processed += 1

        # Recover per-attestation proofs from every processed block.
        # Queue them for publishing only when this node is an aggregator.
        new_store, aggregates = self._deconstruct_block_into_store(new_store, block)
        if self.is_aggregator:
            self._pending_block_aggregates.extend(aggregates)

        # Write-through persistence: synchronous and optional.
        if self.database is not None:
            self._persist_block(new_store, block.block)

        return new_store

    def _persist_block(self, store: Store, block: Block) -> None:
        """
        Persist the block, its state, indices, and chain pointers atomically.

        - A crash mid-batch would leave the database inconsistent.
        - The single batch guarantees all-or-nothing persistence per block import.
        """
        if self.database is None:
            return

        # The block root is the SSZ Merkle root of the block.
        #
        # It is the canonical key under which everything block-related is addressed.
        block_root = hash_tree_root(block)

        # All writes inside the with-block commit together or roll back together.
        #
        # A crash mid-batch leaves the database exactly as it was before entry.
        with self.database.batch_write():
            # The block itself, keyed by its root.
            self.database.put_block(block, block_root)

            # The post-state lands on disk only when the store actually has it.
            #
            # Light clients and observers may discard old states from memory.
            post_state = store.states.get(block_root)
            if post_state is not None:
                self.database.put_state(post_state, block_root)

                # Reverse index: state root -> block root.
                #
                # - Block-to-state is intrinsic: a block header carries its state root.
                # - State-to-block needs this explicit lookup table.
                #
                # Example: checkpoint sync flow.
                #
                #   1. Operator hands the node a trusted state root S.
                #   2. Node downloads the state matching S from a snapshot peer.
                #   3. Node looks up S in this index, returning the block root B.
                #   4. Forkchoice anchors at B and resumes from there.
                state_root = hash_tree_root(post_state)
                self.database.put_block_root_by_state_root(state_root, block_root)

            # Chain-position pointers, updated atomically with the block write.
            #
            # On restart these tell us where the chain ended last session.
            #
            # The node can resume forkchoice without re-deriving from scratch.
            self.database.put_block_root_by_slot(block.slot, block_root)
            self.database.put_head_root(store.head)
            self.database.put_justified_checkpoint(store.latest_justified)
            self.database.put_finalized_checkpoint(store.latest_finalized)

            # Prune data below the finalized boundary, which can never revert.
            # The slot > 0 guard spares genesis, the startup anchor block.
            # Keep the finalized root: it becomes the new on-disk anchor after pruning.
            if store.latest_finalized.slot > Slot(0):
                self.database.prune_before_slot(
                    store.latest_finalized.slot,
                    keep_roots=frozenset({store.latest_finalized.root}),
                )

    def has_root(self, root: Bytes32) -> bool:
        """Return True if the block root is present in the current store."""
        return root in self.store.blocks

    def head_slot(self) -> Slot:
        """Return the slot of the current canonical head."""
        return self.store.blocks[self.store.head].slot

    async def on_peer_status(self, peer_id: PeerId, status: Status) -> None:
        """Record a peer's chain status and move to SYNCING if needed."""
        self.peer_manager.update_status(peer_id, status)

        # Already syncing; nothing to re-trigger.
        if self.state == SyncState.SYNCING:
            return

        # Need at least one peer's finalized slot to compare against.
        network_finalized = self.peer_manager.get_network_finalized_slot()
        if network_finalized is None:
            return

        # Two conditions move us into SYNCING:
        # - the network has finalized blocks we lack (we are behind)
        # - we are still IDLE and must enter SYNCING before any gossip is accepted
        head_slot = self.store.blocks[self.store.head].slot
        if network_finalized > head_slot or self.state == SyncState.IDLE:
            await self._transition_to(SyncState.SYNCING)

    async def on_gossip_block(
        self,
        block: SignedBlock,
        peer_id: PeerId | None,
    ) -> None:
        """Route a gossip-received block to head-sync and replay buffered votes."""
        if not self.state.accepts_gossip:
            logger.debug(
                "Rejecting gossip block from %s: state %s does not accept gossip",
                peer_id,
                self.state.name,
            )
            return

        logger.info(
            "Block received from peer %s slot=%s (state=%s)",
            peer_id,
            block.block.slot,
            self.state.name,
        )

        if self._head_sync is None:
            raise RuntimeError("HeadSync not initialized")

        # Head-sync either processes the block now or caches it pending backfill.
        new_store = await self._head_sync.on_gossip_block(
            block=block,
            peer_id=peer_id,
            store=self.store,
        )

        # None means the block was cached pending an unknown parent.
        # The processed path never awaits, so no clock tick can change the store before write-back.
        if new_store is not None:
            block_root = hash_tree_root(block.block)
            logger.info(
                "Block processed slot=%s root=%s from peer %s",
                block.block.slot,
                block_root.hex(),
                peer_id,
            )
            self.store = new_store
            # A new block may unlock attestations buffered earlier; retry them.
            self._replay_pending_attestations()

            # Publish aggregates recovered from this block, or drop them when no publisher is wired.
            block_aggregates = self._pending_block_aggregates
            self._pending_block_aggregates = []
            if self.publish_aggregated_attestation is not None:
                for signed_attestation in block_aggregates:
                    await self.publish_aggregated_attestation(signed_attestation)

        # Gossip may deliver the final block needed to reach finalized.
        await self._check_sync_complete()

    async def on_gossip_attestation(
        self,
        attestation: SignedAttestation,
        peer_id: PeerId | None = None,
    ) -> None:
        """Integrate a single-validator attestation into forkchoice."""
        # Without peer information we cannot assess validity context.
        if not self.state.accepts_gossip:
            return

        slot = attestation.data.slot
        validator_index = attestation.validator_index
        peer_str = str(peer_id) if peer_id is not None else "local"
        logger.info(
            "Attestation received from peer %s slot=%s validator=%s",
            peer_str,
            slot,
            validator_index,
        )

        # Aggregator role requires both an active validator and operator opt-in.
        is_aggregator_role = self.store.validator_index is not None and self.is_aggregator

        # The store validates the signature and updates branch weights.
        #
        # A missing block buffers for replay.
        # Any permanent rejection is logged and dropped.
        # A genuine bug raises some other exception and propagates uncaught.
        try:
            self.store = self._integrate_gossip_attestation(attestation, is_aggregator_role)
            metrics.lean_attestations_valid_total.labels(source="gossip").inc()
            logger.info(
                "Attestation from peer %s slot=%s validator=%s: validation and signature ok",
                peer_str,
                slot,
                validator_index,
            )
        except UnknownAttestationBlockError as missing_block:
            metrics.lean_attestations_invalid_total.labels(source="gossip").inc()
            logger.warning(
                "Attestation from peer %s slot=%s validator=%s: %s",
                peer_str,
                slot,
                validator_index,
                missing_block,
            )
            # Cap drops oldest on overflow: newer attestations are likelier to land soon.
            self._pending_attestations.append(attestation)
        except SpecRejectionError as rejection:
            metrics.lean_attestations_invalid_total.labels(source="gossip").inc()
            logger.warning(
                "Attestation from peer %s slot=%s validator=%s: rejected: %s",
                peer_str,
                slot,
                validator_index,
                rejection,
            )

    async def on_gossip_aggregated_attestation(
        self,
        signed_attestation: SignedAggregatedAttestation,
        peer_id: PeerId | None = None,
    ) -> None:
        """Integrate an aggregated attestation into forkchoice."""
        # Without peer information we cannot assess validity context.
        if not self.state.accepts_gossip:
            return

        slot = signed_attestation.data.slot
        peer_str = str(peer_id) if peer_id is not None else "local"
        logger.info(
            "Aggregated attestation received from peer %s slot=%s",
            peer_str,
            slot,
        )

        # The store:
        # - verifies the aggregated signature,
        # - credits weight to every validator covered by the aggregate.
        #
        # A missing block buffers for replay.
        # Any permanent rejection is logged and dropped.
        # A genuine bug raises some other exception and propagates uncaught.
        try:
            self.store = self._integrate_gossip_aggregated_attestation(signed_attestation)
            logger.info(
                "Aggregated attestation from peer %s slot=%s: validation and signature ok",
                peer_str,
                slot,
            )
        except UnknownAttestationBlockError as missing_block:
            logger.warning(
                "Aggregated attestation from peer %s slot=%s: %s",
                peer_str,
                slot,
                missing_block,
            )
            # Cap drops oldest on overflow: newer aggregates are likelier to land soon.
            self._pending_aggregated_attestations.append(signed_attestation)
        except SpecRejectionError as rejection:
            logger.warning(
                "Aggregated attestation from peer %s slot=%s: rejected: %s",
                peer_str,
                slot,
                rejection,
            )

    def _integrate_gossip_attestation(
        self,
        attestation: SignedAttestation,
        is_aggregator_role: bool,
    ) -> Store:
        """
        Process a single-validator attestation, flagging a missing block as retryable.

        A rejection naming an unseen source, target, or head block becomes the retryable type.
        Every other rejection propagates unchanged, and so does any genuine bug.
        """
        try:
            return self.spec.on_gossip_attestation(
                self.store,
                signed_attestation=attestation,
                is_aggregator=is_aggregator_role,
            )
        except SpecRejectionError as rejection:
            if rejection.reason in BUFFERABLE_REJECTION_REASONS:
                raise UnknownAttestationBlockError(str(rejection)) from rejection
            raise

    def _integrate_gossip_aggregated_attestation(
        self,
        signed_attestation: SignedAggregatedAttestation,
    ) -> Store:
        """
        Process an aggregated attestation, flagging a missing block as retryable.

        A rejection naming an unseen source, target, or head block becomes the retryable type.
        Every other rejection propagates unchanged, and so does any genuine bug.
        """
        try:
            return self.spec.on_gossip_aggregated_attestation(self.store, signed_attestation)
        except SpecRejectionError as rejection:
            if rejection.reason in BUFFERABLE_REJECTION_REASONS:
                raise UnknownAttestationBlockError(str(rejection)) from rejection
            raise

    def _replay_pending_attestations(self) -> None:
        """Retry buffered attestations after a block is processed."""
        # Aggregator role for this replay matches the live gossip path.
        is_aggregator_role = self.store.validator_index is not None and self.is_aggregator

        # Drain the queue into a local and iterate it.
        # Successful retries disappear into the store.
        # Retries whose block is still missing re-append to the now-empty field.
        #
        # Example: queue is [A (target=T1), B (target=T2)]; a block carrying T1 just landed.
        #   - A succeeds: T1 is in the store, A is consumed.
        #   - B fails:    T2 still missing, B is re-appended.
        # Post-loop queue: [B].
        #
        # A retry that became permanently invalid is dropped, not re-buffered.
        # A genuine bug raises some other exception and propagates uncaught.
        pending = self._pending_attestations
        self._pending_attestations = deque(maxlen=MAX_PENDING_ATTESTATIONS)
        for attestation in pending:
            try:
                self.store = self._integrate_gossip_attestation(attestation, is_aggregator_role)
            except UnknownAttestationBlockError:
                self._pending_attestations.append(attestation)
            except SpecRejectionError:
                pass

        # Same mechanism for aggregated attestations.
        pending_aggregate = self._pending_aggregated_attestations
        self._pending_aggregated_attestations = deque(maxlen=MAX_PENDING_ATTESTATIONS)
        for signed_attestation in pending_aggregate:
            try:
                self.store = self._integrate_gossip_aggregated_attestation(signed_attestation)
            except UnknownAttestationBlockError:
                self._pending_aggregated_attestations.append(signed_attestation)
            except SpecRejectionError:
                pass

    def _deconstruct_block_into_store(
        self,
        store: Store,
        block: SignedBlock,
    ) -> tuple[Store, list[SignedAggregatedAttestation]]:
        """Recover each block attestation's proof and fold it into the local pool."""
        block_attestations = block.block.body.attestations
        if not block_attestations:
            return store, []

        # Resolving the proof's keys needs the parent state's validator set.
        parent_state = store.states.get(block.block.parent_root)
        if parent_state is None:
            return store, []
        validators = parent_state.validators

        # Per-message key layout: one entry per body attestation, then the proposer.
        # Built once to avoid quadratic work across the splits below.
        public_keys_per_message: list[list[PublicKey]] = []
        for attestation in block_attestations:
            public_keys_per_message.append(
                [
                    PublicKey.decode_bytes(validators[validator_index].attestation_public_key)
                    for validator_index in attestation.aggregation_bits.to_validator_indices()
                ]
            )
        public_keys_per_message.append(
            [PublicKey.decode_bytes(validators[block.block.proposer_index].proposal_public_key)]
        )

        # Index local partials by data root.
        # Equal data from different code paths may not share a dict key.
        local_proofs_by_root: dict[Bytes32, list[SingleMessageAggregate]] = {}
        for attestation_data, proofs in store.latest_new_aggregated_payloads.items():
            local_proofs_by_root.setdefault(hash_tree_root(attestation_data), []).extend(proofs)

        # Working copy: shallow-copy the dict and its sets to keep the store immutable.
        new_payloads: dict[AttestationData, set[SingleMessageAggregate]] = {
            pending_data: set(pending_proofs)
            for pending_data, pending_proofs in store.latest_new_aggregated_payloads.items()
        }
        aggregates: list[SignedAggregatedAttestation] = []

        for attestation in block_attestations:
            attestation_data = attestation.data

            # Skip targets at or behind justified, which can no longer advance justification.
            if attestation_data.target.slot <= store.latest_justified.slot:
                continue

            data_root = hash_tree_root(attestation_data)
            block_participants = set(attestation.aggregation_bits.to_validator_indices())

            local_proofs = local_proofs_by_root.get(data_root, [])
            local_union: set = set()
            for proof in local_proofs:
                local_union |= set(proof.participants.to_validator_indices())

            # Act only when the block adds validators not already held.
            if not (block_participants - local_union):
                continue

            try:
                # The split does not return the bits, so pass the block attestation's own.
                block_single_message_aggregate = block.proof.split_by_message(
                    message=data_root,
                    public_keys_per_message=public_keys_per_message,
                    participants=attestation.aggregation_bits,
                )

                if local_proofs:
                    # Folding is order-invariant: the merged bitfield is positional and ascending.
                    # Byte-distinct proofs across orderings all verify against the same key set.
                    combined = SingleMessageAggregate.aggregate(
                        children=[
                            (
                                child,
                                [
                                    PublicKey.decode_bytes(
                                        validators[validator_index].attestation_public_key
                                    )
                                    for validator_index in child.participants.to_validator_indices()
                                ],
                            )
                            for child in (block_single_message_aggregate, *local_proofs)
                        ],
                        raw_xmss=[],
                        message=data_root,
                        slot=attestation_data.slot,
                    )
                else:
                    combined = block_single_message_aggregate
            except (AggregationError, AssertionError, KeyError, ValueError) as exception:
                logger.debug("Post-block re-aggregation failed for %s: %s", data_root, exception)
                continue

            # The combined proof subsumes every local partial that fed it.
            # Drop those now-redundant partials sharing this data root.
            if local_proofs:
                superseded = set(local_proofs)
                for key in list(new_payloads):
                    if hash_tree_root(key) != data_root:
                        continue
                    remaining = new_payloads[key] - superseded
                    if remaining:
                        new_payloads[key] = remaining
                    else:
                        del new_payloads[key]

            new_payloads.setdefault(attestation_data, set()).add(combined)
            aggregates.append(SignedAggregatedAttestation(data=attestation_data, proof=combined))

        if aggregates:
            store = store.model_copy(update={"latest_new_aggregated_payloads": new_payloads})

        return store, aggregates

    async def _check_sync_complete(self) -> None:
        """Move to SYNCED once head has reached finalized and no orphans remain."""
        if self.state != SyncState.SYNCING:
            return

        # Orphans imply pending backfill requests, so we are not yet caught up.
        if self.block_cache.orphan_count > 0:
            return

        network_finalized = self.peer_manager.get_network_finalized_slot()
        if network_finalized is None:
            return

        head_slot = self.store.blocks[self.store.head].slot

        # Head may sit above finalized via unfinalized gossip blocks.
        #
        # The completion threshold is reaching finalized, not equality.
        if head_slot >= network_finalized:
            await self._transition_to(SyncState.SYNCED)

    async def _transition_to(self, new_state: SyncState) -> None:
        """
        Transition to a new sync state, rejecting invalid moves.

        Two invariants are enforced:

        - No self-transitions: a transition must change the current state.
        - No IDLE -> SYNCED shortcut: SYNCING must run before SYNCED is reached.

        Every other (from, to) pair is allowed, including any state -> IDLE.
        """
        forbidden = new_state == self.state or (
            self.state == SyncState.IDLE and new_state == SyncState.SYNCED
        )
        if forbidden:
            raise ValueError(f"Invalid state transition: {self.state.name} -> {new_state.name}")

        self.state = new_state
