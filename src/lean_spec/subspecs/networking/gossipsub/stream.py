"""
Gossipsub Stream Management
==========================

Stream handling for gossipsub RPC exchange.

This module manages:

- Sending RPCs to peers (length-prefixed framing)
- Receiving RPCs from peers (buffered parsing)
- Broadcasting subscriptions to all peers

References:
-----------
- Gossipsub v1.1: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any

from lean_spec.subspecs.networking.gossipsub.rpc import (
    RPC,
    create_graft_rpc,
    create_subscription_rpc,
)
from lean_spec.subspecs.networking.transport import PeerId
from lean_spec.subspecs.networking.varint import decode_varint, encode_varint

if TYPE_CHECKING:
    from lean_spec.subspecs.networking.gossipsub.behavior import GossipsubBehavior

logger = logging.getLogger(__name__)


async def send_rpc(behavior: GossipsubBehavior, peer_id: PeerId, rpc: RPC) -> None:
    """Send an RPC to a peer on the outbound stream."""
    state = behavior._peers.get(peer_id)
    if state is None or state.outbound_stream is None:
        # Expected during stream setup - peer might only have inbound stream yet.
        # The outbound stream will be established shortly.
        logger.debug("Cannot send RPC to %s: no outbound stream yet", peer_id)
        return

    try:
        data = rpc.encode()
        # Length-prefix the RPC (varint + data)
        frame = encode_varint(len(data)) + data
        logger.debug(
            "Sending RPC to %s: %d bytes (subs=%d, msgs=%d)",
            peer_id,
            len(frame),
            len(rpc.subscriptions),
            len(rpc.publish),
        )
        state.outbound_stream.write(frame)
        await state.outbound_stream.drain()
        logger.debug("RPC sent and drained to %s", peer_id)
        state.last_rpc_time = time.time()
    except Exception as e:
        logger.warning("Failed to send RPC to %s: %s", peer_id, e)


async def receive_loop(behavior: GossipsubBehavior, peer_id: PeerId, stream: Any) -> None:
    """Receive and process RPCs from a peer."""
    from lean_spec.subspecs.networking.gossipsub.handlers import handle_rpc

    buffer = bytearray()
    logger.debug("Starting receive loop for peer %s", peer_id)

    try:
        while behavior._running and peer_id in behavior._peers:
            try:
                chunk = await stream.read()
                if not chunk:
                    logger.debug("Receive loop got empty chunk from %s, exiting", peer_id)
                    break
                logger.debug("Received %d bytes from %s", len(chunk), peer_id)
                buffer.extend(chunk)

                # Try to parse complete RPCs
                while buffer:
                    try:
                        # Read length prefix
                        if len(buffer) < 1:
                            break
                        length, varint_size = decode_varint(bytes(buffer), 0)
                        if len(buffer) < varint_size + length:
                            break

                        # Extract and parse RPC
                        rpc_data = bytes(buffer[varint_size : varint_size + length])
                        buffer = buffer[varint_size + length :]

                        rpc = RPC.decode(rpc_data)
                        logger.debug(
                            "Received RPC from %s: subs=%d, msgs=%d, ctrl=%s",
                            peer_id,
                            len(rpc.subscriptions),
                            len(rpc.publish),
                            bool(rpc.control),
                        )
                        await handle_rpc(behavior, peer_id, rpc)
                    except Exception as e:
                        logger.warning("Error parsing RPC from %s: %s", peer_id, e)
                        break

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("Error receiving from %s: %s", peer_id, e)
                break

    finally:
        # Clean up peer on disconnect
        await behavior.remove_peer(peer_id)


async def broadcast_subscription(behavior: GossipsubBehavior, topic: str, subscribe: bool) -> None:
    """Broadcast subscription change to all peers."""
    rpc = create_subscription_rpc([topic], subscribe)

    # Only send to peers we have outbound streams for
    for peer_id, state in behavior._peers.items():
        if state.outbound_stream is not None:
            await behavior._send_rpc(peer_id, rpc)

    # If subscribing, send GRAFT to eligible peers (must have outbound stream)
    if subscribe:
        eligible = [
            p
            for p, s in behavior._peers.items()
            if topic in s.subscriptions and s.outbound_stream is not None
        ][: behavior.params.d]

        if eligible:
            graft_rpc = create_graft_rpc([topic])
            for peer_id in eligible:
                behavior.mesh.add_to_mesh(topic, peer_id)
                await behavior._send_rpc(peer_id, graft_rpc)
