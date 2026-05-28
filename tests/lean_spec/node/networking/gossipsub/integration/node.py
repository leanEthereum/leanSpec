"""Test node wrapper for GossipsubBehavior integration tests.

Wraps a GossipsubBehavior with connection helpers, event collection,
and message waiting utilities.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from lean_spec.node.networking import PeerId
from lean_spec.node.networking.gossipsub.behavior import (
    GossipsubBehavior,
    GossipsubMessageEvent,
    GossipsubPeerEvent,
)
from lean_spec.node.networking.gossipsub.parameters import GossipsubParameters
from lean_spec.node.networking.gossipsub.types import TopicId

from .stream import create_stream_pair


@dataclass
class GossipsubTestNode:
    """Wraps a GossipsubBehavior for integration testing.

    Collects received messages and peer events, and provides
    helpers for connecting to other nodes and waiting for messages.
    """

    peer_id: PeerId
    behavior: GossipsubBehavior
    received_messages: list[GossipsubMessageEvent] = field(default_factory=list)
    peer_events: list[GossipsubPeerEvent] = field(default_factory=list)

    # Wakeup signal for tests waiting on messages.
    # An asyncio.Event gives instant notification without polling loops.
    _message_signal: asyncio.Event = field(default_factory=asyncio.Event)
    _collector_task: asyncio.Task[None] | None = field(default=None, repr=False)

    @classmethod
    def create(cls, name: str, params: GossipsubParameters | None = None) -> GossipsubTestNode:
        """Create a test node with the given name and parameters."""
        peer_id = PeerId.from_base58(name)
        behavior = GossipsubBehavior(params=params or GossipsubParameters())
        return cls(peer_id=peer_id, behavior=behavior)

    async def start(self) -> None:
        """Start the behavior and event collector.

        The collector runs as a background task so events are captured
        continuously. Without it, the internal event queue would fill up
        and tests could not inspect received messages.
        """
        await self.behavior.start()
        self._collector_task = asyncio.create_task(self._collect_events())

    async def stop(self) -> None:
        """Stop the behavior and event collector."""
        await self.behavior.stop()
        if self._collector_task and not self._collector_task.done():
            self._collector_task.cancel()
            try:
                await self._collector_task
            except asyncio.CancelledError:
                pass

    def subscribe(self, topic: TopicId) -> None:
        """Subscribe to a topic."""
        self.behavior.subscribe(topic)

    def unsubscribe(self, topic: TopicId) -> None:
        """Unsubscribe from a topic."""
        self.behavior.unsubscribe(topic)

    async def publish(self, topic: TopicId, data: bytes) -> None:
        """Publish a message to a topic."""
        await self.behavior.publish(topic, data)

    async def connect_to(self, other: GossipsubTestNode) -> None:
        """Establish bidirectional gossipsub streams with another node.

        Creates two stream pairs (one per direction) and registers
        them with both behaviors. This mirrors real libp2p where
        each side has separate inbound and outbound streams.
        """
        # Libp2p uses separate streams per direction.
        # Each peer needs one stream for sending and one for receiving.
        # That means two stream pairs and four registration calls total.

        # Pair 1: self -> other (self writes, other reads)
        out_self, in_other = create_stream_pair()

        # Pair 2: other -> self (other writes, self reads)
        out_other, in_self = create_stream_pair()

        # Registration order matters.
        # Inbound streams start a receive loop. Outbound streams send
        # subscription RPCs immediately. The receiver must be listening
        # before the sender pushes data, or RPCs are lost.
        await other.behavior.add_peer(self.peer_id, in_other, inbound=True)  # type: ignore[arg-type]
        await self.behavior.add_peer(other.peer_id, out_self, inbound=False)  # type: ignore[arg-type]
        await self.behavior.add_peer(other.peer_id, in_self, inbound=True)  # type: ignore[arg-type]
        await other.behavior.add_peer(self.peer_id, out_other, inbound=False)  # type: ignore[arg-type]

        # Let async tasks process queued RPCs.
        await asyncio.sleep(0.05)

    async def wait_for_message(
        self, topic: str | None = None, timeout: float = 5.0
    ) -> GossipsubMessageEvent:
        """Wait for a message to arrive, optionally filtered by topic."""
        deadline = asyncio.get_event_loop().time() + timeout

        while True:
            # Check already-collected messages before waiting.
            for msg in self.received_messages:
                if topic is None or msg.topic == topic:
                    return msg

            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(
                    f"No message received on topic={topic!r} within {timeout}s "
                    f"(have {len(self.received_messages)} messages)"
                )

            # Sleep until the collector signals a new message or deadline expires.
            # Using an Event avoids busy-wait polling.
            self._message_signal.clear()
            try:
                await asyncio.wait_for(self._message_signal.wait(), timeout=remaining)
            except TimeoutError:
                raise TimeoutError(
                    f"No message received on topic={topic!r} within {timeout}s "
                    f"(have {len(self.received_messages)} messages)"
                ) from None

    async def wait_for_messages(
        self, count: int, topic: str | None = None, timeout: float = 5.0
    ) -> list[GossipsubMessageEvent]:
        """Wait until at least `count` messages arrive."""
        deadline = asyncio.get_event_loop().time() + timeout

        while True:
            matching = [m for m in self.received_messages if topic is None or m.topic == topic]
            if len(matching) >= count:
                return matching[:count]

            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(
                    f"Expected {count} messages on topic={topic!r}, got {len(matching)} "
                    f"within {timeout}s"
                )

            self._message_signal.clear()
            try:
                await asyncio.wait_for(self._message_signal.wait(), timeout=remaining)
            except TimeoutError:
                matching = [m for m in self.received_messages if topic is None or m.topic == topic]
                if len(matching) >= count:
                    return matching[:count]
                raise TimeoutError(
                    f"Expected {count} messages on topic={topic!r}, got {len(matching)} "
                    f"within {timeout}s"
                ) from None

    async def trigger_heartbeat(self) -> None:
        """Manually trigger one heartbeat cycle."""
        await self.behavior._heartbeat()

    def get_mesh_peers(self, topic: str) -> set[PeerId]:
        """Get the set of mesh peers for a topic."""
        return self.behavior.mesh.get_mesh_peers(TopicId(topic))

    def get_mesh_size(self, topic: str) -> int:
        """Get the number of mesh peers for a topic."""
        return len(self.get_mesh_peers(topic))

    def message_count(self, topic: str | None = None) -> int:
        """Count received messages, optionally filtered by topic."""
        if topic is None:
            return len(self.received_messages)
        return sum(1 for m in self.received_messages if m.topic == topic)

    def clear_messages(self) -> None:
        """Clear all collected messages."""
        self.received_messages.clear()

    async def _collect_events(self) -> None:
        """Background task that collects events from the behavior.

        Runs for the lifetime of the node. Sorts events into typed lists
        so tests can query them without async boilerplate.
        """
        while True:
            try:
                event = await self.behavior.get_next_event()
                if event is None:
                    break
                if isinstance(event, GossipsubMessageEvent):
                    self.received_messages.append(event)
                    # Wake any test blocked in wait_for_message.
                    self._message_signal.set()
                elif isinstance(event, GossipsubPeerEvent):
                    self.peer_events.append(event)
            except asyncio.CancelledError:
                break
