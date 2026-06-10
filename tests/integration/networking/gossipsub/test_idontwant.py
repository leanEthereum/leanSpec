"""
IDONTWANT protocol tests.

IDONTWANT is a gossipsub v1.2 optimization for large messages.
When a node receives a large message, it tells its other mesh peers
"I already have this, don't send it to me." This saves bandwidth
by preventing redundant transmission of bulky payloads.
"""

from __future__ import annotations

import asyncio

import pytest

from lean_spec.node.networking.gossipsub.behavior import (
    IDONTWANT_SIZE_THRESHOLD,
    GossipsubMessageEvent,
)
from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.types import TopicId
from tests.integration.networking.gossipsub.conftest import fast_params
from tests.integration.networking.gossipsub.network import GossipsubTestNetwork

TOPIC = TopicId("test/idontwant")


@pytest.mark.asyncio
async def test_large_message_triggers_idontwant(
    network: GossipsubTestNetwork,
) -> None:
    """A message >= IDONTWANT_SIZE_THRESHOLD triggers IDONTWANT to mesh peers."""
    params = fast_params()
    nodes = await network.create_nodes(3, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=3)

    # Heartbeat clears dont_want_ids every cycle.
    # Disable it so IDONTWANT state is still visible when we inspect.
    for node in nodes:
        if node.behavior._heartbeat_task:
            node.behavior._heartbeat_task.cancel()
            try:
                await node.behavior._heartbeat_task
            except asyncio.CancelledError:
                pass
            node.behavior._heartbeat_task = None

    # Exceed the threshold so the receiver triggers IDONTWANT.
    large_data = b"x" * (IDONTWANT_SIZE_THRESHOLD + 1024)
    message_id = GossipsubMessage.compute_id(TOPIC.encode("utf-8"), large_data)
    await nodes[0].publish(TOPIC, large_data)

    for node in nodes[1:]:
        message = await node.wait_for_message(TOPIC, timeout=5.0)
        assert message == GossipsubMessageEvent(
            peer_id=message.peer_id, topic=TOPIC, data=large_data, message_id=message_id
        )

    # Brief pause for IDONTWANT RPCs to propagate.
    await asyncio.sleep(0.1)

    # When B receives the large message, B tells its other mesh peers:
    # "I already have this message, don't send it to me."
    # Each peer stores that message ID in its local record of B.
    # If that peer later tried to forward the same message to B, it skips B.
    idontwant_found = False
    for node in nodes:
        for peer_state in node.behavior._peers.values():
            if peer_state.dont_want_ids:
                idontwant_found = True
                break
    assert idontwant_found, "Expected at least one peer to have dont_want_ids set"


@pytest.mark.asyncio
async def test_small_message_no_idontwant(
    network: GossipsubTestNetwork,
) -> None:
    """A message smaller than the threshold does NOT trigger IDONTWANT."""
    params = fast_params()
    nodes = await network.create_nodes(3, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=3)

    # IDONTWANT overhead is not worth it for small messages.
    # Sending the control message costs nearly as much as the message itself.
    small_data = b"tiny"
    assert len(small_data) < IDONTWANT_SIZE_THRESHOLD

    await nodes[0].publish(TOPIC, small_data)

    for node in nodes[1:]:
        await node.wait_for_message(TOPIC, timeout=3.0)

    await asyncio.sleep(0.2)

    # No dont_want_ids should be set.
    for node in nodes:
        for peer_state in node.behavior._peers.values():
            assert not peer_state.dont_want_ids, (
                f"dont_want_ids should be empty for small messages: {peer_state.dont_want_ids}"
            )


@pytest.mark.asyncio
async def test_idontwant_prevents_redundant_forward(
    network: GossipsubTestNetwork,
) -> None:
    """4 nodes: IDONTWANT prevents duplicate large message delivery."""

    # With 4 fully connected nodes, node 0 publishes a large message.
    # Nodes 1, 2, 3 each receive it and immediately announce IDONTWANT to their other mesh peers.
    #
    # This suppresses redundant forwards:
    # without IDONTWANT, each node would also get the same message
    # relayed by the other receivers.
    params = fast_params()
    nodes = await network.create_nodes(4, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=5)

    large_data = b"y" * (IDONTWANT_SIZE_THRESHOLD + 512)
    message_id = GossipsubMessage.compute_id(TOPIC.encode("utf-8"), large_data)
    await nodes[0].publish(TOPIC, large_data)

    for node in nodes[1:]:
        message = await node.wait_for_message(TOPIC, timeout=5.0)
        assert message == GossipsubMessageEvent(
            peer_id=message.peer_id, topic=TOPIC, data=large_data, message_id=message_id
        )

    # Verify each node received exactly once, not duplicated by redundant forwards.
    await asyncio.sleep(0.5)
    for node in nodes[1:]:
        assert node.message_count(TOPIC) == 1, (
            f"{node.peer_id}: received {node.message_count(TOPIC)} (expected 1)"
        )
