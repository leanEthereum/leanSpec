"""In-memory doubles for testing transport, networking, and sync layers."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import cast

from lean_spec.node.chain.clock import SlotClock
from lean_spec.node.networking import PeerId
from lean_spec.node.networking.peer import PeerInfo
from lean_spec.node.networking.service.events import NetworkEvent
from lean_spec.node.networking.types import ConnectionState
from lean_spec.node.storage import Database
from lean_spec.node.sync.block_cache import BlockCache
from lean_spec.node.sync.peer_manager import PeerManager
from lean_spec.node.sync.service import SyncService
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import (
    Checkpoint,
    RejectionReason,
    Slot,
    SpecRejectionError,
    ValidatorIndex,
)
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.containers import (
    Block,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    State,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Bytes32, Uint64


@dataclass
class MockNetworkRequester:
    """Network double that serves pre-loaded blocks and logs every request."""

    blocks_by_root: dict[Bytes32, SignedBlock] = field(default_factory=dict)
    """Blocks available to serve, keyed by block root."""

    blocks_by_slot: dict[Slot, SignedBlock] = field(default_factory=dict)
    """Blocks available to serve, keyed by slot."""

    root_request_log: list[tuple[PeerId, list[Bytes32]]] = field(default_factory=list)
    """Each by-root request received, as a peer and the requested roots."""

    range_request_log: list[tuple[PeerId, Slot, Uint64]] = field(default_factory=list)
    """Each by-range request received, as a peer, start slot, and count."""

    should_fail: bool = False
    """When true, requests raise a connection error instead of returning blocks."""

    async def request_blocks_by_root(
        self,
        peer_id: PeerId,
        roots: list[Bytes32],
    ) -> list[SignedBlock]:
        """Return the available blocks for the requested roots."""
        self.root_request_log.append((peer_id, roots))
        if self.should_fail:
            raise ConnectionError("Network failed")
        return [self.blocks_by_root[root] for root in roots if root in self.blocks_by_root]

    async def request_blocks_by_range(
        self,
        peer_id: PeerId,
        start_slot: Slot,
        count: Uint64,
    ) -> list[SignedBlock]:
        """Return the available blocks across a slot range."""
        self.range_request_log.append((peer_id, start_slot, count))
        if self.should_fail:
            raise ConnectionError("Network failed")

        blocks: list[SignedBlock] = []
        for offset in range(int(count)):
            slot = start_slot + Slot(offset)
            if slot in self.blocks_by_slot:
                blocks.append(self.blocks_by_slot[slot])
        return blocks

    def add_block(self, block: SignedBlock) -> Bytes32:
        """Register a block for serving and return its root."""
        root = hash_tree_root(block.block)
        self.blocks_by_root[root] = block
        self.blocks_by_slot[block.block.slot] = block
        return root


@dataclass
class MockEventSource:
    """Event source double that yields a predefined list of events."""

    events: list[NetworkEvent] = field(default_factory=list)
    """Events yielded in order by async iteration."""

    _index: int = field(default=0, init=False)
    _published: list[tuple[str, bytes]] = field(default_factory=list, init=False)

    def __aiter__(self) -> MockEventSource:
        """Return self as the async iterator."""
        return self

    async def __anext__(self) -> NetworkEvent:
        """Yield the next event, or stop when exhausted."""
        if self._index >= len(self.events):
            raise StopAsyncIteration
        event = self.events[self._index]
        self._index += 1
        return event

    async def publish(self, topic: str, data: bytes) -> None:
        """Record a published payload under its topic."""
        self._published.append((topic, data))


@dataclass
class _MockBlock:
    """Terminal genesis block stub carrying only the slot used in lookups."""

    slot: Slot = field(default_factory=lambda: Slot(0))


@dataclass
class MockForkchoiceStore:
    """
    In-memory forkchoice store double for sync-service tests.

    One instance plays two roles at once.
    It answers reads for the head, blocks, and checkpoints.
    It also processes incoming blocks and attestations.

    Processing reads its own fields, not a separate store.
    So the leading store argument the protocol passes is accepted and ignored.
    """

    head: Bytes32 = field(default_factory=Bytes32.zero)
    """Root of the head block fork choice currently selects."""

    safe_target: Bytes32 = field(default_factory=Bytes32.zero)
    """Root a validator is currently safe to attest to."""

    head_slot: Slot = field(default_factory=lambda: Slot(0))
    """Slot of the head block."""

    validator_index: ValidatorIndex | None = None
    """Owning validator index, or none for an observer."""

    latest_justified: Checkpoint = field(
        default_factory=lambda: Checkpoint(root=Bytes32.zero(), slot=Slot(0))
    )
    """Highest justified checkpoint observed."""

    latest_finalized: Checkpoint = field(
        default_factory=lambda: Checkpoint(root=Bytes32.zero(), slot=Slot(0))
    )
    """Highest finalized checkpoint observed."""

    blocks: dict[Bytes32, Block | _MockBlock] = field(default_factory=dict)
    """Known blocks, keyed by root."""

    states: dict[Bytes32, State] = field(default_factory=dict)
    """Post-state of each block, keyed by root."""

    reject_attestation: Callable[[SignedAttestation], bool] | None = None
    """When it returns true for an attestation, processing raises a spec rejection."""

    reject_aggregated_attestation: Callable[[SignedAggregatedAttestation], bool] | None = None
    """When it returns true for an aggregate, processing raises a spec rejection."""

    rejection_reason: RejectionReason = RejectionReason.UNKNOWN_TARGET_BLOCK
    """Reason carried by a triggered rejection.
    The default names a missing block, which the sync service buffers for replay.
    Set a permanent reason to exercise the logged-and-dropped path."""

    on_block_post_state: State | None = None
    """Post-state recorded for each processed block, when set."""

    advance_justified_on_block: bool = False
    """Whether processing a block advances the justified checkpoint to it."""

    advance_finalized_on_block: bool = False
    """Whether processing a block advances the finalized checkpoint to it."""

    received_attestations: list[SignedAttestation] = field(default_factory=list)
    """Attestations accepted so far, in arrival order."""

    received_aggregated_attestations: list[SignedAggregatedAttestation] = field(
        default_factory=list
    )
    """Aggregated attestations accepted so far, in arrival order."""

    def __post_init__(self) -> None:
        """Seed the store with a genesis block stub at the head root."""
        self.blocks.setdefault(self.head, _MockBlock(slot=self.head_slot))

    def on_block(self, _store: Store, signed_block: SignedBlock) -> MockForkchoiceStore:
        """Record a block as the new head and apply the configured side effects."""
        root = hash_tree_root(signed_block.block)
        self.blocks[root] = signed_block.block
        self.head = root
        # The double has no real safe-target rule, so the head doubles as it.
        self.safe_target = root
        self.head_slot = signed_block.block.slot
        if self.on_block_post_state is not None:
            self.states[root] = self.on_block_post_state
        if self.advance_justified_on_block:
            self.latest_justified = Checkpoint(root=root, slot=signed_block.block.slot)
        if self.advance_finalized_on_block:
            self.latest_finalized = Checkpoint(root=root, slot=signed_block.block.slot)
        return self

    def on_gossip_attestation(
        self,
        _store: Store,
        signed_attestation: SignedAttestation,
        is_aggregator: bool = False,
    ) -> MockForkchoiceStore:
        """Record a gossip attestation, unless the reject predicate fires."""
        if self.reject_attestation is not None and self.reject_attestation(signed_attestation):
            raise SpecRejectionError(self.rejection_reason, "simulated rejection")
        self.received_attestations.append(signed_attestation)
        return self

    def on_gossip_aggregated_attestation(
        self,
        _store: Store,
        signed_attestation: SignedAggregatedAttestation,
    ) -> MockForkchoiceStore:
        """Record an aggregated attestation, unless the reject predicate fires."""
        if self.reject_aggregated_attestation is not None and self.reject_aggregated_attestation(
            signed_attestation
        ):
            raise SpecRejectionError(self.rejection_reason, "simulated rejection")
        self.received_aggregated_attestations.append(signed_attestation)
        return self


@dataclass(frozen=True)
class RecordedCall:
    """One database call captured by the recording database double."""

    name: str
    """Name of the database method invoked."""

    args: tuple[object, ...]
    """Positional arguments the method received."""

    kwargs: Mapping[str, object]
    """Keyword arguments the method received."""


class RecordingSyncDatabase:
    """Database double that records the calls a persisting writer makes."""

    def __init__(self) -> None:
        """Start with an empty call log."""
        self.calls: list[RecordedCall] = []

    def _record(self, name: str, *args: object, **kwargs: object) -> None:
        self.calls.append(RecordedCall(name=name, args=args, kwargs=MappingProxyType(dict(kwargs))))

    def calls_inside_batch(self) -> list[RecordedCall]:
        """Calls recorded between a batch-write enter and its matching exit."""
        collected: list[RecordedCall] = []
        in_batch = False
        for call in self.calls:
            if call.name == "batch_write_enter":
                in_batch = True
                continue
            if call.name == "batch_write_exit":
                break
            if in_batch:
                collected.append(call)
        return collected

    @contextmanager
    def batch_write(self) -> Iterator[None]:
        """Record the boundaries of a batched write."""
        self._record("batch_write_enter")
        try:
            yield
        finally:
            self._record("batch_write_exit")

    def put_block(self, block: object, root: object) -> None:
        """Record a block write."""
        self._record("put_block", block, root)

    def put_state(self, state: object, root: object) -> None:
        """Record a state write."""
        self._record("put_state", state, root)

    def put_block_root_by_state_root(self, state_root: object, block_root: object) -> None:
        """Record a state-root to block-root index write."""
        self._record("put_block_root_by_state_root", state_root, block_root)

    def put_block_root_by_slot(self, slot: object, root: object) -> None:
        """Record a slot to block-root index write."""
        self._record("put_block_root_by_slot", slot, root)

    def put_head_root(self, root: object) -> None:
        """Record a head-root write."""
        self._record("put_head_root", root)

    def put_justified_checkpoint(self, checkpoint: object) -> None:
        """Record a justified-checkpoint write."""
        self._record("put_justified_checkpoint", checkpoint)

    def put_finalized_checkpoint(self, checkpoint: object) -> None:
        """Record a finalized-checkpoint write."""
        self._record("put_finalized_checkpoint", checkpoint)

    def prune_before_slot(self, slot: object, *, keep_roots: frozenset[Bytes32]) -> int:
        """Record a prune request and report zero rows removed."""
        self._record("prune_before_slot", slot, keep_roots=keep_roots)
        return 0


def create_mock_sync_service(
    peer_id: PeerId,
    *,
    database: Database | None = None,
    genesis_start: bool = False,
) -> SyncService:
    """Build a sync service backed by a fake store, spec, and network."""
    peer_manager = PeerManager()
    peer_manager.add_peer(PeerInfo(peer_id=peer_id, state=ConnectionState.CONNECTED))

    # One double fills both roles the service expects.
    # Its fields answer store reads.
    # Its methods answer the processing the service drives.
    forkchoice_double = MockForkchoiceStore()

    return SyncService(
        store=cast(Store, forkchoice_double),
        peer_manager=peer_manager,
        block_cache=BlockCache(),
        clock=SlotClock(genesis_time=Uint64(0), time_fn=lambda: 1000.0),
        network=MockNetworkRequester(),
        spec=cast(LstarSpec, forkchoice_double),
        database=database,
        genesis_start=genesis_start,
    )
