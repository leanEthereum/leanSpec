"""Heartbeat mechanics integration tests.

The heartbeat is the periodic maintenance cycle of gossipsub.
Each tick, a node adjusts its mesh, ages its caches, and clears
transient state like IDONTWANT entries.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from lean_spec.node.networking.gossipsub.behavior import IDONTWANT_SIZE_THRESHOLD
from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.types import TopicId

from .conftest import fast_params
from .network import GossipsubTestNetwork

TOPIC = TopicId("test/heartbeat")


@pytest.mark.asyncio
async def test_multiple_heartbeats_stabilize(
    network: GossipsubTestNetwork,
) -> None:
    """10 nodes: meshes converge after 5 heartbeat rounds."""
    params = fast_params()
    await network.create_nodes(10, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)

    # Each heartbeat round, nodes GRAFT under-connected meshes and
    # PRUNE over-connected ones. After several rounds, all meshes
    # should settle within [D_low, D_high].
    await network.stabilize_mesh(TOPIC, rounds=5)

    for node in network.nodes:
        size = node.get_mesh_size(TOPIC)
        assert params.d_low <= size <= params.d_high, (
            f"{node.peer_id}: mesh size {size} outside [{params.d_low}, {params.d_high}]"
        )


@pytest.mark.asyncio
async def test_cache_aging_evicts_messages(
    network: GossipsubTestNetwork,
) -> None:
    """After mcache_len heartbeat shifts, cached messages are evicted."""

    # The message cache is a sliding window of mcache_len slots.
    # Each heartbeat shifts the window forward by one slot.
    # After mcache_len shifts, the oldest slot falls off the window.
    params = fast_params(mcache_len=3)
    nodes = await network.create_nodes(2, params)
    await network.start_all()
    await nodes[0].connect_to(nodes[1])
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=2)

    publisher = nodes[0]
    await publisher.publish(TOPIC, b"will-be-evicted")

    # Compute the message ID for lookup.
    msg_id = GossipsubMessage.compute_id(TOPIC.encode("utf-8"), b"will-be-evicted")
    assert publisher.behavior.message_cache.has(msg_id)

    # Shift the cache mcache_len times. The message was in slot 0.
    # After 3 shifts, slot 0 falls off the window and the message is gone.
    for _ in range(params.mcache_len):
        publisher.behavior.message_cache.shift()

    assert not publisher.behavior.message_cache.has(msg_id)


@pytest.mark.asyncio
async def test_fanout_expiry(
    network: GossipsubTestNetwork,
) -> None:
    """Fanout entries are cleaned up after TTL expires."""

    # Fanout tracks peers for topics we publish to but are NOT subscribed to.
    # Without a TTL, stale fanout entries would reference peers that left
    # the topic long ago.
    params = fast_params(fanout_ttl_secs=1)
    nodes = await network.create_nodes(2, params)
    await network.start_all()
    await nodes[0].connect_to(nodes[1])

    # Only node B subscribes. Node A publishes without subscribing
    # (uses fanout).
    nodes[1].subscribe(TOPIC)
    await asyncio.sleep(0.1)

    await nodes[0].publish(TOPIC, b"fanout-msg")
    assert nodes[0].behavior.mesh.fanout_topics == {TOPIC}

    # Simulate TTL expiry by cleaning up with a future timestamp.
    nodes[0].behavior.mesh.cleanup_fanouts(
        params.fanout_ttl_secs, time.time() + params.fanout_ttl_secs + 1
    )

    assert not nodes[0].behavior.mesh.fanout_topics, "Fanout should be cleaned up"


@pytest.mark.asyncio
async def test_dont_want_cleared_each_heartbeat(
    network: GossipsubTestNetwork,
) -> None:
    """dont_want_ids are cleared after each heartbeat."""

    # Disable automatic heartbeat (999s interval) so dont_want_ids
    # survive long enough for us to inspect them.
    # We then manually trigger one heartbeat and verify it clears them.
    params = fast_params(heartbeat_interval_secs=999)
    nodes = await network.create_nodes(3, params)
    await network.start_all()
    await network.connect_full()
    await network.subscribe_all(TOPIC)
    await network.stabilize_mesh(TOPIC, rounds=3)

    # Publish a large message to trigger IDONTWANT between peers.
    large_data = b"z" * (IDONTWANT_SIZE_THRESHOLD + 512)
    await nodes[0].publish(TOPIC, large_data)
    await asyncio.sleep(0.3)

    # Precondition: at least one peer must have dont_want_ids populated.
    # Without this, clearing an already-empty set proves nothing.
    has_dont_want = any(
        peer_state.dont_want_ids for node in nodes for peer_state in node.behavior._peers.values()
    )
    assert has_dont_want, "No dont_want_ids populated after large message propagation"

    # Heartbeat must reset dont_want_ids every cycle.
    # Stale entries would block future legitimate forwards of new messages
    # that happen to share the same ID space.
    await network.trigger_all_heartbeats()

    for node in nodes:
        for peer_state in node.behavior._peers.values():
            assert not peer_state.dont_want_ids, (
                f"dont_want_ids not cleared after heartbeat: {peer_state.dont_want_ids}"
            )
