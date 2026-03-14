"""
Mock classes for testing transport and networking layers.

Each mock provides minimal implementations for isolated testing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lean_spec.subspecs.containers import SignedBlock
from lean_spec.subspecs.containers.attestation import SignedAttestation
from lean_spec.subspecs.containers.attestation.attestation import SignedAggregatedAttestation
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.service.events import NetworkEvent
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32


class MockNetworkRequester:
    """Mock network that returns pre-configured blocks and tracks requests."""

    def __init__(self) -> None:
        """Initialize with empty block store and request log."""
        self.blocks_by_root: dict[Bytes32, SignedBlock] = {}
        self.request_log: list[tuple[PeerId, list[Bytes32]]] = []
        self.should_fail: bool = False

    async def request_blocks_by_root(
        self,
        peer_id: PeerId,
        roots: list[Bytes32],
    ) -> list[SignedBlock]:
        """Return blocks for requested roots."""
        self.request_log.append((peer_id, roots))
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

    def add_block(self, block: SignedBlock) -> Bytes32:
        """Add a block to the mock network. Returns its root."""
        root = hash_tree_root(block.message)
        self.blocks_by_root[root] = block
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
    """Minimal block stub with a slot attribute for mock store lookups."""

    slot: Slot = field(default_factory=lambda: Slot(0))


@dataclass
class _MockCheckpoint:
    """Minimal checkpoint stub with a slot attribute for mock store access."""

    root: Bytes32 = field(default_factory=Bytes32.zero)
    slot: Slot = field(default_factory=lambda: Slot(0))


class MockForkchoiceStore:
    """Mock forkchoice store for sync service testing.

    Tracks blocks, attestations, and head state without running real
    forkchoice logic. Methods return self so the SyncService can assign
    the result back (matching the real Store's immutable-update pattern).
    """

    def __init__(self, head_slot: int = 0) -> None:
        """Initialize with a genesis block stub at Bytes32.zero()."""
        genesis_root = Bytes32.zero()
        self.blocks: dict[Bytes32, object] = {genesis_root: _MockBlock(slot=Slot(head_slot))}
        self.head: Bytes32 = genesis_root
        self.head_slot: Slot = Slot(head_slot)
        self._attestations_received: list[SignedAttestation] = []
        self.validator_id = None
        self.latest_justified = _MockCheckpoint()
        self.latest_finalized = _MockCheckpoint()
        self.states: dict[Bytes32, object] = {}

    def on_block(
        self,
        block: SignedBlock,
        **kwargs: object,
    ) -> MockForkchoiceStore:
        """Track block additions. Returns self for assignment chaining."""
        root = hash_tree_root(block.message)
        self.blocks[root] = block.message
        self.head = root
        self.head_slot = block.message.slot
        return self

    def on_gossip_attestation(
        self,
        signed_attestation: SignedAttestation,
        *,
        is_aggregator: bool = False,
    ) -> MockForkchoiceStore:
        """Track attestation additions. Returns self for assignment chaining."""
        self._attestations_received.append(signed_attestation)
        return self

    def on_gossip_aggregated_attestation(
        self,
        signed_attestation: SignedAggregatedAttestation,
    ) -> MockForkchoiceStore:
        """Track aggregated attestation additions. Returns self for assignment chaining."""
        return self
