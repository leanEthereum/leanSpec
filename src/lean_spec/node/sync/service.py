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
    """
    An attestation references a source, target, or head block the store has not seen.

    A later block can still supply the missing block.
    The sync service buffers the attestation and replays it after the next block.
    This is the only attestation rejection worth retrying, so it carries its own type.
    """


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
    """Async callback for publishing aggregated attestations to the network.

    Defaults to None so tests and offline runs do not need a publisher wired.
    Assign after construction once NetworkService is built.
    """

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
    """Combined aggregates recovered from processed blocks.

    Every processed block is deconstructed during block processing, which
    queues its combined aggregates when this node is in the aggregator
    role. The gossip umbrella drains and publishes them after the store
    is updated.
    """

    def __post_init__(self) -> None:
        """Wire sub-components and apply the genesis-start state hint."""
        self._init_components()

        # Genesis validators already hold the full genesis state.
        #
        # They process gossip blocks immediately without a peer status exchange.
        if self.genesis_start:
            self.state = SyncState.SYNCING

    def _init_components(self) -> None:
        """Wire the backfill and head-sync sub-components."""
        # Backfill reads the store through self.
        #
        # So, the live reference is observed as we reassign store after each block.
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

        # Deconstruct every processed block, regardless of how it arrived.
        #
        # Gossip, head-sync, and backfilled descendants all funnel through
        # here. Recovering the per-attestation proofs from the merged block
        # proof and writing them into the pool is what gives a catching-up
        # node block-imported attestation weight in fork choice.
        # Non-aggregators do the work for their local pool only and never
        # republish, so the gossip queue is only fed when this node is in
        # the aggregator role.
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

            # Prune historical data below the finalized boundary.
            #
            # Finalized blocks can never be reverted.
            # Keeping pre-finalized data on disk wastes space for no consensus value.
            #
            # **Why the slot > 0 guard:**
            # - Genesis is the only finalized slot at startup.
            # - Pruning before genesis would remove the chain's anchor block.
            #
            # **Why the finalized root stays in keep_roots:**
            # - The finalized block is the new on-disk anchor after pruning.
            # - Removing it would orphan the database from the chain it tracks.
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
        gossip_block_outcome, new_store = await self._head_sync.on_gossip_block(
            block=block,
            peer_id=peer_id,
            store=self.store,
        )

        # Only update our store if the block was actually processed.
        #
        # A block may be cached instead of processed if its parent is unknown.
        if gossip_block_outcome.processed:
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
            await self._publish_pending_block_aggregates()

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
        """
        Recover per-attestation proofs from a processed block.

        On block import we already trust the block-attestation participant
        bitfields via spec on_block signature verification. The block carries
        one merged multi-message aggregate proof binding every attestation in its body.

        For each block attestation that covers validators not already held
        in the given store:

        1. Extract that data's single-message aggregate proof
           out of the block's multi-message aggregate proof.
        2. Merge it with all local partial single-message aggregate proofs for the same data
           into one single-message aggregate proof whose participant bits are the union.
        3. Write the combined proof into the pending pool.

        If the data was never seen locally, the extracted single-message aggregate is used
        as-is.

        Runs for every node, including non-validators, so the per-attestation
        proofs reach the local pool and contribute fork-choice weight after
        the next acceptance tick. Publishing is left to the caller and only
        the aggregator role should drain the returned list onto gossip.

        Returns:
            The store (possibly unchanged if no recovery was needed) and
            the combined aggregates produced by this call.
        """
        block_attestations = list(block.block.body.attestations)
        if not block_attestations:
            return store, []

        # The multi-message aggregate proof was built against the parent state's validator set.
        # Without it we cannot resolve the public_key layout the proof was bound to.
        parent_state = store.states.get(block.block.parent_root)
        if parent_state is None:
            return store, []
        validators = parent_state.validators

        # Build the per-message public_key layout once.
        # The layout is invariant per block: one entry per body attestation
        # in order, then the proposer entry. Hoisted out of the per-att loop
        # to avoid quadratic work when many block attestations need splitting.
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

        # Index local partial single-message aggregate proofs by AttestationData root. Equivalent
        # AttestationData instances from different code paths may not share a
        # dict key, so match on the hash tree root instead.
        local_proofs_by_root: dict[Bytes32, list[SingleMessageAggregate]] = {}
        for attestation_data, proofs in store.latest_new_aggregated_payloads.items():
            local_proofs_by_root.setdefault(hash_tree_root(attestation_data), []).extend(proofs)

        # Working copy of the pending pool.
        # The combined proof is retained locally so the block-sourced
        # aggregate survives without depending on gossip loopback. Shallow
        # copy the dict and its inner sets to preserve store immutability.
        new_payloads: dict[AttestationData, set[SingleMessageAggregate]] = {
            pending_data: set(pending_proofs)
            for pending_data, pending_proofs in store.latest_new_aggregated_payloads.items()
        }
        aggregates: list[SignedAggregatedAttestation] = []

        for attestation in block_attestations:
            attestation_data = attestation.data

            # Only spend a split on attestations that can still move
            # justification forward. A target at or behind the store's
            # justified checkpoint cannot, so skip it.
            if attestation_data.target.slot <= store.latest_justified.slot:
                continue

            data_root = hash_tree_root(attestation_data)
            block_participants = set(attestation.aggregation_bits.to_validator_indices())

            local_proofs = local_proofs_by_root.get(data_root, [])
            local_union: set = set()
            for proof in local_proofs:
                local_union |= set(proof.participants.to_validator_indices())

            # Only act when the block covers validators we do not already
            # hold. An empty local_union also covers data never seen locally.
            if not (block_participants - local_union):
                continue

            try:
                # The split takes the bits from the block attestation this
                # component binds, since the Rust binding does not return them.
                block_single_message_aggregate = block.proof.split_by_message(
                    message=data_root,
                    public_keys_per_message=public_keys_per_message,
                    participants=attestation.aggregation_bits,
                )

                if local_proofs:
                    # The local proofs arrive in set-iteration order.
                    # That order is not stable across nodes.
                    # Folding them stays order-invariant for consensus.
                    #
                    # The merged participant bitfield is positional and ascending.
                    # It names the same validators regardless of child order.
                    #
                    # Folding may emit byte-distinct proofs across orderings.
                    # Every ordering verifies against that same canonical key set.
                    # No consensus rule compares these re-merged proofs by bytes.
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
                    # Data unseen locally: nothing to merge, use as-is.
                    combined = block_single_message_aggregate
            except (AggregationError, AssertionError, KeyError, ValueError) as exception:
                logger.debug("Post-block re-aggregation failed for %s: %s", data_root, exception)
                continue

            # The combined proof is a superset of every local partial that
            # fed it, so those partials are now redundant. Drop them from
            # the pool (across any data key sharing this root) and keep only
            # the higher-coverage proof.
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

    async def _publish_pending_block_aggregates(self) -> None:
        """
        Gossip the aggregates recovered from processed blocks.

        Every processed block is deconstructed in the block wrapper, which
        writes the recovered proofs into the store and queues the combined
        aggregates here when this node acts as an aggregator. This drains
        that queue onto the network.
        """
        if not self._pending_block_aggregates:
            return
        pending = self._pending_block_aggregates
        self._pending_block_aggregates = []
        # No publisher wired (tests, offline runs): drop the drained aggregates.
        if self.publish_aggregated_attestation is None:
            return
        for signed_attestation in pending:
            await self.publish_aggregated_attestation(signed_attestation)

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
