"""
Mock classes for testing transport and networking layers.

Each mock provides minimal implementations for isolated testing.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from lean_spec.node.networking import PeerId
from lean_spec.node.networking.service.events import NetworkEvent
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Slot
from lean_spec.spec.forks.lstar.containers import (
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Bytes32, Uint64


class StoreInterceptingSpec(LstarSpec):
    """Spec stub that forwards consensus calls to the store argument."""

    def on_block(  # type: ignore[override]
        self, store: Any, signed_block: Any, *args: Any, **kwargs: Any
    ) -> Any:
        """Forward to store.on_block."""
        kwargs.pop("scheme", None)
        return store.on_block(signed_block, *args, **kwargs)

    def on_gossip_attestation(  # type: ignore[override]
        self, store: Any, signed_attestation: Any, *args: Any, **kwargs: Any
    ) -> Any:
        """Forward to store.on_gossip_attestation."""
        kwargs.pop("scheme", None)
        return store.on_gossip_attestation(signed_attestation, *args, **kwargs)

    def on_gossip_aggregated_attestation(  # type: ignore[override]
        self, store: Any, signed_attestation: Any, *args: Any, **kwargs: Any
    ) -> Any:
        """Forward to store.on_gossip_aggregated_attestation."""
        return store.on_gossip_aggregated_attestation(signed_attestation, *args, **kwargs)

    def tick_interval(  # type: ignore[override]
        self, store: Any, has_proposal: bool, is_aggregator: bool = False
    ) -> Any:
        """Forward to store.tick_interval."""
        return store.tick_interval(has_proposal, is_aggregator)


class MockNetworkRequester:
    """Mock network that returns pre-configured blocks and tracks requests."""

    def __init__(self) -> None:
        """Initialize with empty block store and request logs."""
        self.blocks_by_root: dict[Bytes32, SignedBlock] = {}
        self.blocks_by_slot: dict[Slot, SignedBlock] = {}
        self.root_request_log: list[tuple[PeerId, list[Bytes32]]] = []
        self.range_request_log: list[tuple[PeerId, Slot, Uint64]] = []
        self.should_fail: bool = False

    async def request_blocks_by_root(
        self,
        peer_id: PeerId,
        roots: list[Bytes32],
    ) -> list[SignedBlock]:
        """Return blocks for requested roots."""
        self.root_request_log.append((peer_id, roots))
        if self.should_fail:
            raise ConnectionError("Network failed")
        return [self.blocks_by_root[r] for r in roots if r in self.blocks_by_root]

    async def request_block_by_root(
        self,
        peer_id: PeerId,
        root: Bytes32,
    ) -> SignedBlock | None:
        """Return a single block by root."""
        return self.blocks_by_root.get(root)

    async def request_blocks_by_range(
        self,
        peer_id: PeerId,
        start_slot: Slot,
        count: Uint64,
    ) -> list[SignedBlock]:
        """Return blocks for requested slot range."""
        self.range_request_log.append((peer_id, start_slot, count))
        if self.should_fail:
            raise ConnectionError("Network failed")

        blocks: list[SignedBlock] = []
        for i in range(int(count)):
            slot = start_slot + Slot(i)
            if slot in self.blocks_by_slot:
                blocks.append(self.blocks_by_slot[slot])
        return blocks

    def add_block(self, block: SignedBlock) -> Bytes32:
        """Add a block to the mock network. Returns its root."""
        root = hash_tree_root(block.block)
        self.blocks_by_root[root] = block
        self.blocks_by_slot[block.block.slot] = block
        return root


@dataclass
class MockEventSource:
    """Mock source that yields predefined events."""

    events: list[NetworkEvent] = field(default_factory=list)
    _index: int = field(default=0, init=False)
    _published: list[tuple[str, bytes]] = field(default_factory=list, init=False)

    def __aiter__(self) -> MockEventSource:
        """Return self as async iterator."""
        return self

    async def __anext__(self) -> NetworkEvent:
        """Yield the next event or stop."""
        if self._index >= len(self.events):
            raise StopAsyncIteration
        event = self.events[self._index]
        self._index += 1
        return event

    async def publish(self, topic: str, data: bytes) -> None:
        """Record published data."""
        self._published.append((topic, data))


@dataclass
class _MockBlock:
    """Minimal block stub with slot and parent_root for mock store lookups."""

    slot: Slot = field(default_factory=lambda: Slot(0))
    parent_root: Bytes32 = field(default_factory=Bytes32.zero)


class MockForkchoiceStore:
    """Mock forkchoice store for sync service testing.

    Tracks blocks, attestations, and head state without running real
    forkchoice logic. Methods return self so the SyncService can assign
    the result back (matching the real Store's immutable-update pattern).

    Optional `reject_*` predicates return True to simulate validation
    failure (`KeyError`), e.g. unknown attestation target.

    The `on_block_*` flags let tests simulate forkchoice side-effects of
    block processing (post-state indexing, justified or finalized advance)
    without injecting a custom block processor.
    """

    def __init__(self, head_slot: int = 0) -> None:
        """Initialize with a genesis block stub at Bytes32.zero()."""
        genesis_root = Bytes32.zero()
        self.blocks: dict[Bytes32, object] = {genesis_root: _MockBlock(slot=Slot(head_slot))}
        self.head: Bytes32 = genesis_root
        self.safe_target: Bytes32 = genesis_root
        self.head_slot: Slot = Slot(head_slot)
        self._attestations_received: list[SignedAttestation] = []
        self._aggregated_attestations_received: list[SignedAggregatedAttestation] = []
        self.validator_index = None
        self.latest_justified = Checkpoint(root=Bytes32.zero(), slot=Slot(0))
        self.latest_finalized = Checkpoint(root=Bytes32.zero(), slot=Slot(0))
        self.states: dict[Bytes32, object] = {}
        self.reject_attestation: Callable[[SignedAttestation], bool] | None = None
        self.reject_aggregated_attestation: Callable[[SignedAggregatedAttestation], bool] | None = (
            None
        )
        self.on_block_post_state: object | None = None
        """When set, on_block stores this object as states[block_root]."""
        self.advance_justified_on_block: bool = False
        """When True, on_block advances latest_justified to the new block."""
        self.advance_finalized_on_block: bool = False
        """When True, on_block advances latest_finalized to the new block."""

    def on_block(
        self,
        block: SignedBlock,
        **kwargs: object,
    ) -> MockForkchoiceStore:
        """Track block additions. Returns self for assignment chaining."""
        root = hash_tree_root(block.block)
        self.blocks[root] = block.block
        self.head = root
        # The mock has no real safe-target rule; head doubles as safe-target.
        self.safe_target = root
        self.head_slot = block.block.slot
        if self.on_block_post_state is not None:
            self.states[root] = self.on_block_post_state
        if self.advance_justified_on_block:
            self.latest_justified = Checkpoint(root=root, slot=block.block.slot)
        if self.advance_finalized_on_block:
            self.latest_finalized = Checkpoint(root=root, slot=block.block.slot)
        return self

    def on_gossip_attestation(
        self,
        signed_attestation: SignedAttestation,
        *,
        is_aggregator: bool = False,
    ) -> MockForkchoiceStore:
        """Track attestation additions. Returns self for assignment chaining."""
        if self.reject_attestation is not None and self.reject_attestation(signed_attestation):
            raise KeyError("simulated missing block")
        self._attestations_received.append(signed_attestation)
        return self

    def on_gossip_aggregated_attestation(
        self,
        signed_attestation: SignedAggregatedAttestation,
    ) -> MockForkchoiceStore:
        """Track aggregated attestation additions. Returns self for assignment chaining."""
        if self.reject_aggregated_attestation is not None and self.reject_aggregated_attestation(
            signed_attestation
        ):
            raise KeyError("simulated missing block")
        self._aggregated_attestations_received.append(signed_attestation)
        return self


@dataclass(frozen=True)
class RecordedCall:
    """One invocation recorded by RecordingSyncDatabase."""

    name: str
    args: tuple[object, ...]
    kwargs: Mapping[str, object]


class RecordingSyncDatabase:
    """Minimal database double recording calls made by SyncService._persist_block."""

    def __init__(self) -> None:
        self.calls: list[RecordedCall] = []

    def _record(self, name: str, *args: object, **kwargs: object) -> None:
        self.calls.append(
            RecordedCall(
                name=name,
                args=args,
                kwargs=MappingProxyType(dict(kwargs)),
            )
        )

    def calls_inside_batch(self) -> list[RecordedCall]:
        """Calls between the first `batch_write_enter` and matching `batch_write_exit`."""
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
        self._record("batch_write_enter")
        try:
            yield
        finally:
            self._record("batch_write_exit")

    def put_block(self, block: object, root: object) -> None:
        self._record("put_block", block, root)

    def put_state(self, state: object, root: object) -> None:
        self._record("put_state", state, root)

    def put_block_root_by_state_root(self, state_root: object, block_root: object) -> None:
        self._record("put_block_root_by_state_root", state_root, block_root)

    def put_block_root_by_slot(self, slot: object, root: object) -> None:
        self._record("put_block_root_by_slot", slot, root)

    def put_head_root(self, root: object) -> None:
        self._record("put_head_root", root)

    def put_justified_checkpoint(self, checkpoint: object) -> None:
        self._record("put_justified_checkpoint", checkpoint)

    def put_finalized_checkpoint(self, checkpoint: object) -> None:
        self._record("put_finalized_checkpoint", checkpoint)

    def prune_before_slot(self, slot: object, *, keep_roots: frozenset) -> int:
        self._record("prune_before_slot", slot, keep_roots=keep_roots)
        return 0
