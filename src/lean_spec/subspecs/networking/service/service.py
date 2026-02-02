"""
Network service that routes events to sync.

The Problem
-----------
The network layer (libp2p) produces events: blocks arrive via gossip,
peers send status messages, connections come and go. These events need
to reach the consensus layer to update forkchoice state.

The network service is the bridge. It:

1. Consumes events from an abstract source (async iterator)
2. Routes each event to the appropriate sync handler
3. Publishes locally-produced blocks and attestations to peers
4. Runs until stopped or the source exhausts

This means:
- The network layer produces events,
- A routing service dispatches them,
- The consensus layer handles each event type with dedicated logic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lean_spec.snappy import frame_compress
from lean_spec.subspecs.containers import SignedBlockWithAttestation
from lean_spec.subspecs.containers.attestation import SignedAttestation
from lean_spec.subspecs.networking.gossipsub.topic import GossipTopic

from .events import (
    GossipAttestationEvent,
    GossipBlockEvent,
    NetworkEvent,
    NetworkEventSource,
    PeerConnectedEvent,
    PeerDisconnectedEvent,
    PeerStatusEvent,
)

if TYPE_CHECKING:
    from lean_spec.subspecs.sync import SyncService

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NetworkService:
    """
    Routes network events to the sync service and publishes outbound messages.

    This service:

    - Routes inbound events to sync handlers
    - Publishes locally-produced blocks and attestations to the network

    It does not:

    - Manage connections (libp2p handles this)
    - Score peers (libp2p gossipsub handles this)
    - Buffer events (async iteration provides backpressure)
    """

    sync_service: SyncService
    """Sync service that receives routed events."""

    event_source: NetworkEventSource
    """Source of network events (libp2p wrapper or test mock)."""

    fork_digest: str = field(default="0x00000000")
    """Fork digest for gossip topics (4-byte hex string)."""

    _running: bool = field(default=False, repr=False)
    """Whether the event loop is running."""

    _events_processed: int = field(default=0, repr=False)
    """Counter for processed events (for monitoring)."""

    async def run(self) -> None:
        """
        Main event loop - route events until stopped.

        Consumes events from the source and dispatches to handlers.
        The loop exits when:
        - stop() is called
        - The event source raises StopAsyncIteration

        This method is designed to run as a long-lived task.
        """
        self._running = True

        try:
            async for event in self.event_source:
                # Check stop flag after each event to allow graceful shutdown.
                #
                # Without this check, we would have to wait for the next event
                # to arrive before noticing the stop request.
                if not self._running:
                    break

                await self._handle_event(event)
                self._events_processed += 1

        except StopAsyncIteration:
            # Source exhausted - normal termination for finite event sources.
            #
            # - This happens in tests where MockEventSource has a predefined list of events.
            # - In production, the libp2p source runs forever.
            pass

        finally:
            # Always mark as not running when the loop exits.
            #
            # This ensures the flag reflects actual state regardless of
            # whether we exited due to stop() or source exhaustion.
            self._running = False

    async def _handle_event(self, event: NetworkEvent) -> None:
        """
        Route event to appropriate sync service handler.

        Uses pattern matching for clean dispatch. Each event type
        maps to exactly one handler method on SyncService.

        Args:
            event: Network event to route.
        """
        match event:
            case GossipBlockEvent(block=block, peer_id=peer_id):
                # Route gossip blocks to the sync service for processing.
                #
                # SyncService will either:
                # - process immediately (if parent known) or
                # - cache and trigger backfill (if parent unknown).
                await self.sync_service.on_gossip_block(block, peer_id)

            case GossipAttestationEvent(attestation=attestation, peer_id=peer_id):
                #
                # SyncService will validate signature and update forkchoice.
                await self.sync_service.on_gossip_attestation(
                    attestation=attestation,
                    peer_id=peer_id,
                )

            case PeerStatusEvent(peer_id=peer_id, status=status):
                # Route peer status updates to sync service.
                #
                # SyncService uses this to track network consensus and
                # determine if we need to start/continue syncing.
                await self.sync_service.on_peer_status(peer_id, status)

            case PeerConnectedEvent() | PeerDisconnectedEvent():
                # Peer lifecycle events are not yet handled.
                #
                # Future: update peer manager, track connection metrics.
                pass

    def stop(self) -> None:
        """
        Signal the event loop to stop.

        Sets the running flag to False. The run() loop will exit
        after completing the current event (if any).

        Thread-safe: can be called from any thread/task.
        """
        self._running = False

    @property
    def is_running(self) -> bool:
        """Check if the event loop is currently running."""
        return self._running

    @property
    def events_processed(self) -> int:
        """Total events processed since creation."""
        return self._events_processed

    async def publish_block(self, block: SignedBlockWithAttestation) -> None:
        """
        Publish a block to the gossip network.

        Encodes the block as SSZ, compresses with Snappy, and broadcasts
        to all connected peers on the block topic.

        Args:
            block: Signed block to publish.
        """
        topic = GossipTopic.block(self.fork_digest)
        ssz_bytes = block.encode_bytes()
        compressed = frame_compress(ssz_bytes)

        await self.event_source.publish(str(topic), compressed)
        logger.debug("Published block at slot %s", block.message.block.slot)

    async def publish_attestation(self, attestation: SignedAttestation, subnet_id: int) -> None:
        """
        Publish an attestation to the attestation subnet gossip topic.

        Encodes the attestation as SSZ, compresses with Snappy, and broadcasts
        to all connected peers on the attestation subnet topic.

        Args:
            attestation: Signed attestation to publish.
            subnet_id: Subnet ID to publish to.
        """
        topic = GossipTopic.attestation_subnet(self.fork_digest, subnet_id)
        ssz_bytes = attestation.encode_bytes()
        compressed = frame_compress(ssz_bytes)

        await self.event_source.publish(str(topic), compressed)
        logger.debug("Published attestation for slot %s", attestation.message.slot)
