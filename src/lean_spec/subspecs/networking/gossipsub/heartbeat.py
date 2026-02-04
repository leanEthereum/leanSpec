"""
Gossipsub Heartbeat and Mesh Maintenance
========================================

Periodic maintenance tasks for the gossipsub mesh.

The heartbeat runs at regular intervals (default 700ms) and:

1. Maintains mesh sizes (GRAFT if < D_low, PRUNE if > D_high)
2. Sends IHAVE gossip to non-mesh peers
3. Ages the message cache
4. Cleans up seen cache

References:
-----------
- Gossipsub v1.1: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from lean_spec.subspecs.networking.config import PRUNE_BACKOFF
from lean_spec.subspecs.networking.gossipsub.rpc import (
    RPC,
    ControlIHave,
    ControlMessage,
    ControlPrune,
    create_graft_rpc,
)

if TYPE_CHECKING:
    from lean_spec.subspecs.networking.gossipsub.behavior import GossipsubBehavior

logger = logging.getLogger(__name__)


async def heartbeat_loop(behavior: GossipsubBehavior) -> None:
    """Background heartbeat for mesh maintenance."""
    interval = behavior.params.heartbeat_interval_secs

    while behavior._running:
        try:
            await asyncio.sleep(interval)
            await heartbeat(behavior)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning("Heartbeat error: %s", e)


async def heartbeat(behavior: GossipsubBehavior) -> None:
    """
    Perform heartbeat maintenance.

    The heartbeat:

    1. Maintains mesh sizes (GRAFT if < D_low, PRUNE if > D_high)
    2. Sends IHAVE gossip to non-mesh peers
    3. Ages the message cache
    """
    now = time.time()

    for topic in behavior._subscriptions:
        await maintain_mesh(behavior, topic, now)
        await emit_gossip(behavior, topic)

    # Age message cache
    behavior.message_cache.shift()

    # Clean up seen cache
    behavior.seen_cache.cleanup(now)


async def maintain_mesh(behavior: GossipsubBehavior, topic: str, now: float) -> None:
    """Maintain mesh size for a topic."""
    mesh_peers = behavior.mesh.get_mesh_peers(topic)
    mesh_size = len(mesh_peers)

    # Find eligible peers (subscribed to topic, not in mesh, and can send to).
    #
    # IMPORTANT: Only consider peers we can actually send to.
    # If we don't have an outbound stream yet (peer just connected, stream
    # setup still in progress), skip them. They'll become eligible once
    # their outbound stream is established.
    eligible = []
    for peer_id, state in behavior._peers.items():
        # Must have outbound stream to send GRAFT
        if state.outbound_stream is None:
            continue
        if topic in state.subscriptions and peer_id not in mesh_peers:
            # Check backoff
            backoff_until = state.backoff.get(topic, 0)
            if now >= backoff_until:
                eligible.append(peer_id)

    # GRAFT if too few peers
    if mesh_size < behavior.params.d_low and eligible:
        needed = behavior.params.d - mesh_size
        to_graft = eligible[: min(needed, len(eligible))]

        for peer_id in to_graft:
            behavior.mesh.add_to_mesh(topic, peer_id)

        # Send GRAFT
        rpc = create_graft_rpc([topic])
        for peer_id in to_graft:
            await behavior._send_rpc(peer_id, rpc)

        logger.debug("GRAFT %d peers for topic %s", len(to_graft), topic)

    # PRUNE if too many peers
    elif mesh_size > behavior.params.d_high:
        # Keep peers with best scores (for now, just take first D)
        to_prune = list(mesh_peers)[behavior.params.d :]

        for peer_id in to_prune:
            behavior.mesh.remove_from_mesh(topic, peer_id)

        # Send PRUNE
        prune_rpc = RPC(
            control=ControlMessage(prune=[ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)])
        )
        for peer_id in to_prune:
            await behavior._send_rpc(peer_id, prune_rpc)

        logger.debug("PRUNE %d peers for topic %s", len(to_prune), topic)


async def emit_gossip(behavior: GossipsubBehavior, topic: str) -> None:
    """Send IHAVE gossip to non-mesh peers."""
    # Get message IDs from cache
    msg_ids = behavior.message_cache.get_gossip_ids(topic)
    if not msg_ids:
        return

    # Get all connected peers subscribed to this topic (with outbound streams).
    #
    # Only include peers we can actually send to. Peers without outbound
    # streams yet (still setting up) are skipped.
    all_topic_peers = {
        p
        for p, state in behavior._peers.items()
        if topic in state.subscriptions and state.outbound_stream is not None
    }

    # Select D_lazy non-mesh peers
    gossip_peers = behavior.mesh.select_peers_for_gossip(topic, all_topic_peers)
    if not gossip_peers:
        return

    # Send IHAVE
    msg_id_bytes = [msg_id if isinstance(msg_id, bytes) else bytes(msg_id) for msg_id in msg_ids]
    ihave = ControlIHave(topic_id=topic, message_ids=msg_id_bytes)
    rpc = RPC(control=ControlMessage(ihave=[ihave]))

    for peer_id in gossip_peers:
        await behavior._send_rpc(peer_id, rpc)

    logger.debug(
        "IHAVE %d messages to %d peers for topic %s", len(msg_ids), len(gossip_peers), topic
    )
