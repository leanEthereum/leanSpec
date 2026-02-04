"""
Gossipsub Message Handlers
=========================

Handlers for incoming gossipsub RPCs and control messages.

This module processes:

- Subscription changes (peer joined/left topic)
- Published messages (validate, dedupe, forward)
- Control messages (GRAFT, PRUNE, IHAVE, IWANT)

References:
-----------
- Gossipsub v1.1: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from lean_spec.subspecs.networking.config import PRUNE_BACKOFF
from lean_spec.subspecs.networking.gossipsub.rpc import (
    RPC,
    ControlGraft,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    Message,
    SubOpts,
)
from lean_spec.subspecs.networking.transport import PeerId
from lean_spec.types import Bytes20

if TYPE_CHECKING:
    from lean_spec.subspecs.networking.gossipsub.behavior import (
        GossipsubBehavior,
    )

logger = logging.getLogger(__name__)


async def handle_rpc(behavior: GossipsubBehavior, peer_id: PeerId, rpc: RPC) -> None:
    """Handle an incoming RPC."""
    state = behavior._peers.get(peer_id)
    if state is None:
        return

    # Process subscriptions
    for sub in rpc.subscriptions:
        await handle_subscription(behavior, peer_id, sub)

    # Process published messages
    for msg in rpc.publish:
        await handle_message(behavior, peer_id, msg)

    # Process control messages
    if rpc.control:
        await handle_control(behavior, peer_id, rpc.control)


async def handle_subscription(behavior: GossipsubBehavior, peer_id: PeerId, sub: SubOpts) -> None:
    """Handle a subscription change from a peer."""
    from lean_spec.subspecs.networking.gossipsub.behavior import GossipsubPeerEvent

    state = behavior._peers.get(peer_id)
    if state is None:
        return

    if sub.subscribe:
        state.subscriptions.add(sub.topic_id)
        logger.debug("Peer %s subscribed to %s", peer_id, sub.topic_id)
    else:
        state.subscriptions.discard(sub.topic_id)
        # Remove from mesh if they unsubscribed
        behavior.mesh.remove_from_mesh(sub.topic_id, peer_id)
        logger.debug("Peer %s unsubscribed from %s", peer_id, sub.topic_id)

    # Emit event
    await behavior._event_queue.put(
        GossipsubPeerEvent(peer_id=peer_id, topic=sub.topic_id, subscribed=sub.subscribe)
    )


async def handle_message(behavior: GossipsubBehavior, peer_id: PeerId, msg: Message) -> None:
    """Handle a published message from a peer."""
    from lean_spec.subspecs.networking.gossipsub.behavior import GossipsubMessageEvent
    from lean_spec.subspecs.networking.gossipsub.message import GossipsubMessage

    if not msg.topic:
        return

    # Compute message ID
    msg_id = behavior._compute_message_id(msg.topic.encode("utf-8"), msg.data)

    # Check if already seen
    if behavior.seen_cache.has(msg_id):
        return

    # Mark as seen
    behavior.seen_cache.add(msg_id, time.time())

    # Add to cache
    cache_msg = GossipsubMessage(topic=msg.topic.encode("utf-8"), raw_data=msg.data)
    behavior.message_cache.put(msg.topic, cache_msg)

    # Forward to mesh peers (excluding sender)
    if msg.topic in behavior._subscriptions:
        mesh_peers = behavior.mesh.get_mesh_peers(msg.topic)
        forward_rpc = RPC(publish=[msg])

        for mesh_peer in mesh_peers:
            if mesh_peer != peer_id:
                await behavior._send_rpc(mesh_peer, forward_rpc)

    # Emit event to application
    event = GossipsubMessageEvent(
        peer_id=peer_id, topic=msg.topic, data=msg.data, message_id=msg_id
    )
    await behavior._event_queue.put(event)

    # Call handler if set
    if behavior._message_handler:
        behavior._message_handler(event)

    logger.debug("Received message %s from %s on topic %s", msg_id.hex()[:8], peer_id, msg.topic)


async def handle_control(
    behavior: GossipsubBehavior, peer_id: PeerId, control: ControlMessage
) -> None:
    """Handle control messages from a peer."""
    state = behavior._peers.get(peer_id)
    if state is None:
        return

    # Handle GRAFT
    for graft in control.graft:
        await handle_graft(behavior, peer_id, graft)

    # Handle PRUNE
    for prune in control.prune:
        await handle_prune(behavior, peer_id, prune)

    # Handle IHAVE
    for ihave in control.ihave:
        await handle_ihave(behavior, peer_id, ihave)

    # Handle IWANT
    for iwant in control.iwant:
        await handle_iwant(behavior, peer_id, iwant)


async def handle_graft(behavior: GossipsubBehavior, peer_id: PeerId, graft: ControlGraft) -> None:
    """Handle a GRAFT request from a peer."""
    topic = graft.topic_id

    # Check if we're subscribed to the topic
    if topic not in behavior._subscriptions:
        # Send PRUNE - we're not subscribed
        prune = ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)
        prune_rpc = RPC(control=ControlMessage(prune=[prune]))
        await behavior._send_rpc(peer_id, prune_rpc)
        return

    # Check mesh size
    mesh_peers = behavior.mesh.get_mesh_peers(topic)
    if len(mesh_peers) >= behavior.params.d_high:
        # Mesh is full, send PRUNE
        prune = ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)
        prune_rpc = RPC(control=ControlMessage(prune=[prune]))
        await behavior._send_rpc(peer_id, prune_rpc)
        return

    # Accept GRAFT
    behavior.mesh.add_to_mesh(topic, peer_id)
    logger.debug("Accepted GRAFT from %s for topic %s", peer_id, topic)


async def handle_prune(behavior: GossipsubBehavior, peer_id: PeerId, prune: ControlPrune) -> None:
    """Handle a PRUNE notification from a peer."""
    topic = prune.topic_id
    state = behavior._peers.get(peer_id)

    # Remove from mesh
    behavior.mesh.remove_from_mesh(topic, peer_id)

    # Set backoff
    if state and prune.backoff > 0:
        state.backoff[topic] = time.time() + prune.backoff

    logger.debug("Received PRUNE from %s for topic %s (backoff=%ds)", peer_id, topic, prune.backoff)


async def handle_ihave(behavior: GossipsubBehavior, peer_id: PeerId, ihave: ControlIHave) -> None:
    """Handle an IHAVE advertisement from a peer."""
    # Find messages we don't have
    wanted = []
    for msg_id in ihave.message_ids:
        # Convert bytes to Bytes20 for cache lookup
        if len(msg_id) != 20:
            continue
        msg_id_typed = Bytes20(msg_id)
        if not behavior.seen_cache.has(msg_id_typed) and not behavior.message_cache.has(
            msg_id_typed
        ):
            wanted.append(msg_id)

    if not wanted:
        return

    # Send IWANT
    iwant_rpc = RPC(control=ControlMessage(iwant=[ControlIWant(message_ids=wanted)]))
    await behavior._send_rpc(peer_id, iwant_rpc)

    logger.debug("Sent IWANT for %d messages from %s", len(wanted), peer_id)


async def handle_iwant(behavior: GossipsubBehavior, peer_id: PeerId, iwant: ControlIWant) -> None:
    """Handle an IWANT request from a peer."""
    messages = []

    for msg_id in iwant.message_ids:
        # Convert bytes to Bytes20 for cache lookup
        if len(msg_id) != 20:
            continue
        msg_id_typed = Bytes20(msg_id)
        cached = behavior.message_cache.get(msg_id_typed)
        if cached:
            messages.append(Message(topic=cached.topic.decode("utf-8"), data=cached.raw_data))

    if messages:
        rpc = RPC(publish=messages)
        await behavior._send_rpc(peer_id, rpc)

        logger.debug("Sent %d messages in response to IWANT from %s", len(messages), peer_id)
