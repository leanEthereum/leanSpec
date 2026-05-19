"""
Sync service orchestrator.

Drives a node from cold start to active participation in the network.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field

from lean_spec.forks import (
    AttestationData,
    Block,
    LstarSpec,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    Store,
)
from lean_spec.subspecs.chain.clock import SlotClock
from lean_spec.subspecs.metrics import registry as metrics
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.transport.peer_id import PeerId
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.storage import Database
from lean_spec.subspecs.xmss.aggregation import (
    AggregationError,
    TypeOneMultiSignature,
    TypeTwoMultiSignature,
)
from lean_spec.subspecs.xmss.containers import PublicKey
from lean_spec.types import Bytes32, Slot, SubnetId
from lean_spec.types.exceptions import SSZError

from .backfill_sync import BackfillSync, NetworkRequester
from .block_cache import BlockCache
from .config import MAX_PENDING_ATTESTATIONS
from .head_sync import HeadSync
from .peer_manager import PeerManager
from .states import SyncState

logger = logging.getLogger(__name__)


async def _noop_publish_agg(signed_attestation: SignedAggregatedAttestation) -> None:
    """No-op default for aggregated attestation publishing."""


@dataclass(slots=True)
class SyncProgress:
    """
    Current synchronization progress.

    Provides a snapshot of sync state for monitoring and logging.
    """

    state: SyncState
    """Current sync state machine state."""

    local_head_slot: Slot | None = None
    """Slot of our current chain head."""

    network_finalized_slot: Slot | None = None
    """Network consensus on finalized slot (mode of peer reports)."""

    blocks_processed: int = 0
    """Total blocks integrated into Store this session."""

    peers_connected: int = 0
    """Number of connected peers with status."""

    cache_size: int = 0
    """Number of blocks in pending cache."""

    orphan_count: int = 0
    """Number of orphan blocks awaiting parents."""


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

    aggregate_subnet_ids: tuple[SubnetId, ...] = field(default_factory=tuple)
    """
    Extra subnets the aggregator subscribes to on top of its validator-derived one.

    Ignored on non-aggregator nodes, which never import gossip attestations.
    """

    process_block: Callable[[Store, SignedBlock], Store] | None = field(default=None)
    """Block processor function. Defaults to the spec's block processing."""

    publish_aggregated_attestation: Callable[
        [SignedAggregatedAttestation], Coroutine[None, None, None]
    ] = field(default=_noop_publish_agg)
    """Async callback for publishing aggregated attestations to the network.

    Defaults to a no-op so tests and offline runs do not need a publisher wired.
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

    _pending_attestations: list[SignedAttestation] = field(default_factory=list)
    """
    Attestations queued for replay after the next block lands.

    An attestation referencing a not-yet-received block fails validation.

    Buffering avoids dropping votes that arrived slightly out of order.
    """

    _pending_aggregated_attestations: list[SignedAggregatedAttestation] = field(
        default_factory=list
    )
    """
    Aggregated attestations awaiting block processing.

    Same buffering strategy as individual attestations.
    """

    _pending_block_aggregates: list[SignedAggregatedAttestation] = field(default_factory=list)
    """Combined aggregates recovered from processed blocks.

    Every processed block is deconstructed in the block wrapper, which
    queues its combined aggregates when this node is in the aggregator
    role. The gossip umbrella drains and publishes them after the store
    is updated.
    """

    def __post_init__(self) -> None:
        """Bind the default block processor and wire sub-components."""
        # Tests can pass an explicit processor and skip this path.
        if self.process_block is None:
            self.process_block = self._default_process_block

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

        # The wrapper adds counter and persistence tracking around each block.
        self._head_sync = HeadSync(
            block_cache=self.block_cache,
            backfill=self._backfill,
            process_block=self._process_block_wrapper,
        )

    def _default_process_block(self, store: Store, block: SignedBlock) -> Store:
        """Run the spec's block processor and emit forkchoice telemetry."""
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
                while (b := new_store.blocks.get(root)) is not None:
                    seen.add(root)
                    root = b.parent_root
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

        return new_store

    def _process_block_wrapper(
        self,
        store: Store,
        block: SignedBlock,
    ) -> Store:
        """Run the processor, bump the counter, and persist when wired up.

        All block processing flows through one wrapper regardless of which
        processor is configured.
        """
        # Delegate to the actual block processor.
        #
        # The processor validates the block and updates forkchoice state.
        processor = self.process_block
        assert processor is not None
        new_store = processor(store, block)

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
        """Persist the block, its state, indices, and chain pointers atomically.

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

    def get_progress(self) -> SyncProgress:
        """Snapshot the current sync state for monitoring and logging."""
        # Mode of peer-reported finalized slots, or None if too few peers reported.
        network_slot = self.peer_manager.get_network_finalized_slot()

        return SyncProgress(
            state=self.state,
            local_head_slot=self.head_slot(),
            network_finalized_slot=network_slot,
            blocks_processed=self._blocks_processed,
            peers_connected=sum(1 for p in self.peer_manager.get_all_peers() if p.is_connected()),
            cache_size=len(self.block_cache),
            orphan_count=self.block_cache.orphan_count,
        )

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
        result, new_store = await self._head_sync.on_gossip_block(
            block=block,
            peer_id=peer_id,
            store=self.store,
        )

        # Only update our store if the block was actually processed.
        #
        # A block may be cached instead of processed if its parent is unknown.
        if result.processed:
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
        validator_id = attestation.validator_id
        peer_str = str(peer_id) if peer_id is not None else "local"
        logger.info(
            "Attestation received from peer %s slot=%s validator=%s",
            peer_str,
            slot,
            validator_id,
        )

        # Aggregator role requires both an active validator and operator opt-in.
        is_aggregator_role = self.store.validator_id is not None and self.is_aggregator

        # The store validates the signature and updates branch weights.
        #
        # Failures are logged and the event loop continues.
        try:
            self.store = self.spec.on_gossip_attestation(
                self.store,
                signed_attestation=attestation,
                is_aggregator=is_aggregator_role,
            )
            metrics.lean_attestations_valid_total.labels(source="gossip").inc()
            logger.info(
                "Attestation from peer %s slot=%s validator=%s: validation and signature ok",
                peer_str,
                slot,
                validator_id,
            )
        except (AssertionError, KeyError) as e:
            metrics.lean_attestations_invalid_total.labels(source="gossip").inc()
            logger.warning(
                "Attestation from peer %s slot=%s validator=%s: validation or signature failed: %s",
                peer_str,
                slot,
                validator_id,
                e,
            )
            # Target block has not arrived yet; buffer for post-block replay.
            #
            # Cap drops oldest on overflow: newer attestations are likelier to land soon.
            self._pending_attestations.append(attestation)
            if len(self._pending_attestations) > MAX_PENDING_ATTESTATIONS:
                self._pending_attestations = self._pending_attestations[-MAX_PENDING_ATTESTATIONS:]

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
        # Failures are logged and the event loop continues.
        try:
            self.store = self.spec.on_gossip_aggregated_attestation(self.store, signed_attestation)
            logger.info(
                "Aggregated attestation from peer %s slot=%s: validation and signature ok",
                peer_str,
                slot,
            )
        except (AssertionError, KeyError) as e:
            logger.warning(
                "Aggregated attestation from peer %s slot=%s: validation or signature failed: %s",
                peer_str,
                slot,
                e,
            )
            # Target block has not arrived yet; buffer for post-block replay.
            #
            # Cap drops oldest on overflow: newer aggregates are likelier to land soon.
            self._pending_aggregated_attestations.append(signed_attestation)
            if len(self._pending_aggregated_attestations) > MAX_PENDING_ATTESTATIONS:
                self._pending_aggregated_attestations = self._pending_aggregated_attestations[
                    -MAX_PENDING_ATTESTATIONS:
                ]

    def _replay_pending_attestations(self) -> None:
        """Retry buffered attestations after a block is processed."""
        # Aggregator role for this replay matches the live gossip path.
        is_aggregator_role = self.store.validator_id is not None and self.is_aggregator

        # Drain the queue into a local and iterate it.
        # Successful retries disappear into the store.
        # Failed retries re-append to the now-empty field.
        #
        # Example: queue is [A (target=T1), B (target=T2)]; a block carrying T1 just landed.
        #   - A succeeds: T1 is in the store, A is consumed.
        #   - B fails:    T2 still missing, B is re-appended.
        # Post-loop queue: [B].
        pending = self._pending_attestations
        self._pending_attestations = []
        for attestation in pending:
            try:
                self.store = self.spec.on_gossip_attestation(
                    self.store,
                    signed_attestation=attestation,
                    is_aggregator=is_aggregator_role,
                )
            except (AssertionError, KeyError):
                # Block still missing; preserve for the next replay cycle.
                self._pending_attestations.append(attestation)

        # Same mechanism for aggregated attestations.
        pending_agg = self._pending_aggregated_attestations
        self._pending_aggregated_attestations = []
        for signed_attestation in pending_agg:
            try:
                self.store = self.spec.on_gossip_aggregated_attestation(
                    self.store, signed_attestation
                )
            except (AssertionError, KeyError):
                self._pending_aggregated_attestations.append(signed_attestation)

    def _deconstruct_block_into_store(
        self,
        store: Store,
        block: SignedBlock,
    ) -> tuple[Store, list[SignedAggregatedAttestation]]:
        """Recover per-attestation proofs from a processed block.

        On block import we already trust the block-attestation participant
        bitfields via spec on_block signature verification. The block carries
        one merged Type-2 proof binding every attestation in its body.

        For each block attestation that covers validators not already held
        in the given store:

        1. Extract that data's Type-1 proof out of the block's Type-2 proof.
        2. Merge it with all local partial Type-1 proofs for the same data
           into one Type-1 proof whose participant bits are the union.
        3. Write the combined proof into the pending pool.

        If the data was never seen locally, the extracted Type-1 is used
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

        # The Type-2 proof was built against the parent state's validator set.
        # Without it we cannot resolve the pubkey layout the proof was bound to.
        parent_state = store.states.get(block.block.parent_root)
        if parent_state is None:
            return store, []
        validators = parent_state.validators

        # The wrapper must not raise on a malformed proof.
        # The block already passed signature verification upstream, so this
        # catches the realistic SSZ deserialization failure modes only.
        try:
            type_two = TypeTwoMultiSignature.decode_bytes(block.proof.data)
        except (SSZError, ValueError, IndexError) as exc:
            logger.debug("Post-block Type-2 decode failed: %s", exc)
            return store, []

        # Build the per-message pubkey layout once.
        # The layout is invariant per block: one entry per body attestation
        # in order, then the proposer entry. Hoisted out of the per-att loop
        # to avoid quadratic work when many block attestations need splitting.
        public_keys_per_message: list[list[PublicKey]] = []
        for att in block_attestations:
            public_keys_per_message.append(
                [
                    validators[vid].get_attestation_pubkey()
                    for vid in att.aggregation_bits.to_validator_indices()
                ]
            )
        public_keys_per_message.append(
            [validators[block.block.proposer_index].get_proposal_pubkey()]
        )

        # Index local partial Type-1 proofs by AttestationData root. Equivalent
        # AttestationData instances from different code paths may not share a
        # dict key, so match on the hash tree root instead.
        local_proofs_by_root: dict[Bytes32, list[TypeOneMultiSignature]] = {}
        for data, proofs in store.latest_new_aggregated_payloads.items():
            local_proofs_by_root.setdefault(hash_tree_root(data), []).extend(proofs)

        # Working copy of the pending pool.
        # The combined proof is retained locally so the block-sourced
        # aggregate survives without depending on gossip loopback. Shallow
        # copy the dict and its inner sets to preserve store immutability.
        new_payloads: dict[AttestationData, set[TypeOneMultiSignature]] = {
            k: set(v) for k, v in store.latest_new_aggregated_payloads.items()
        }
        aggregates: list[SignedAggregatedAttestation] = []

        for att in block_attestations:
            data = att.data

            # Only spend a split on attestations that can still move
            # justification forward. A target at or behind the store's
            # justified checkpoint cannot, so skip it.
            if data.target.slot <= store.latest_justified.slot:
                continue

            data_root = hash_tree_root(data)
            block_participants = set(att.aggregation_bits.to_validator_indices())

            local_proofs = local_proofs_by_root.get(data_root, [])
            local_union: set = set()
            for proof in local_proofs:
                local_union |= set(proof.participants.to_validator_indices())

            # Only act when the block covers validators we do not already
            # hold. An empty local_union also covers data never seen locally.
            if not (block_participants - local_union):
                continue

            try:
                block_t1 = type_two.split_by_msg(
                    message=data_root,
                    public_keys_per_message=public_keys_per_message,
                )
                # split_by_msg returns an empty participant bitfield; restore
                # the bits from the block attestation this component binds.
                block_t1 = block_t1.model_copy(update={"participants": att.aggregation_bits})

                if local_proofs:
                    combined = TypeOneMultiSignature.aggregate(
                        children=[
                            (
                                child,
                                [
                                    validators[vid].get_attestation_pubkey()
                                    for vid in child.participants.to_validator_indices()
                                ],
                            )
                            for child in (block_t1, *local_proofs)
                        ],
                        raw_xmss=[],
                        xmss_participants=None,
                        message=data_root,
                        slot=data.slot,
                    )
                else:
                    # Data unseen locally: nothing to merge, use as-is.
                    combined = block_t1
            except (AggregationError, AssertionError, KeyError, ValueError) as exc:
                logger.debug("Post-block re-aggregation failed for %s: %s", data_root, exc)
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

            new_payloads.setdefault(data, set()).add(combined)
            aggregates.append(SignedAggregatedAttestation(data=data, proof=combined))

        if aggregates:
            store = store.model_copy(update={"latest_new_aggregated_payloads": new_payloads})

        return store, aggregates

    async def _publish_pending_block_aggregates(self) -> None:
        """Gossip the aggregates recovered from processed blocks.

        Every processed block is deconstructed in the block wrapper, which
        writes the recovered proofs into the store and queues the combined
        aggregates here when this node acts as an aggregator. This drains
        that queue onto the network.
        """
        if not self._pending_block_aggregates:
            return
        pending = self._pending_block_aggregates
        self._pending_block_aggregates = []
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
        """Transition to a new sync state, rejecting invalid moves.

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

    def reset(self) -> None:
        """Return to IDLE and clear caches, counters, and sub-component state."""
        self.state = SyncState.IDLE
        self._blocks_processed = 0

        # Cached blocks may be stale or invalid after a reset.
        self.block_cache.clear()

        # Sub-components hold pending requests and orphan trackers that must clear too.
        if self._backfill is not None:
            self._backfill.reset()
        if self._head_sync is not None:
            self._head_sync.reset()
