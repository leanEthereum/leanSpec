"""Shared test utilities for gossipsub tests."""

from __future__ import annotations

from dataclasses import dataclass, field

from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.gossipsub.behavior import GossipsubBehavior, PeerState
from lean_spec.subspecs.networking.gossipsub.parameters import GossipsubParameters
from lean_spec.subspecs.networking.gossipsub.rpc import RPC


def _peer(name: str) -> PeerId:
    """Create a PeerId from a test name."""
    return PeerId.from_base58(name)


@dataclass
class MockSendCapture:
    """Captures RPCs sent via _send_rpc for assertion."""

    sent: list[tuple[PeerId, RPC]] = field(default_factory=list)

    async def __call__(self, peer_id: PeerId, rpc: RPC) -> None:
        self.sent.append((peer_id, rpc))


class MockOutboundStream:
    """Minimal mock that satisfies outbound stream checks."""

    def write(self, data: bytes) -> None:
        pass

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


def _make_behavior(
    d: int = 8, d_low: int = 6, d_high: int = 12, d_lazy: int = 6
) -> tuple[GossipsubBehavior, MockSendCapture]:
    """Create a behavior with mock send and return (behavior, capture)."""
    params = GossipsubParameters(d=d, d_low=d_low, d_high=d_high, d_lazy=d_lazy)
    behavior = GossipsubBehavior(params=params)
    capture = MockSendCapture()
    behavior._send_rpc = capture  # type: ignore[assignment]
    return behavior, capture


def _add_peer(
    behavior: GossipsubBehavior,
    name: str,
    subscriptions: set[str] | None = None,
    with_stream: bool = True,
) -> PeerId:
    """Add a peer directly to behavior state."""
    peer_id = _peer(name)
    state = PeerState(
        peer_id=peer_id,
        subscriptions=subscriptions or set(),
        outbound_stream=MockOutboundStream() if with_stream else None,
    )
    behavior._peers[peer_id] = state
    return peer_id
