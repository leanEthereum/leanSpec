"""Fixtures for gossipsub integration tests."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

import pytest

from lean_spec.subspecs.networking.gossipsub.parameters import GossipsubParameters

from .network import GossipsubTestNetwork
from .node import GossipsubTestNode


def fast_params(**overrides: int | float | str) -> GossipsubParameters:
    """Create parameters tuned for fast integration tests.

    Uses small mesh degree (D=3) so tests need fewer nodes to fill
    meshes. Short heartbeat (0.05s) keeps test duration low.

    D=3, D_low=2, D_high=5, D_lazy=2, heartbeat=0.05s.
    """
    defaults: dict[str, int | float | str] = {
        "d": 3,
        "d_low": 2,
        "d_high": 5,
        "d_lazy": 2,
        "heartbeat_interval_secs": 0.05,
        "fanout_ttl_secs": 5,
        "mcache_len": 6,
        "mcache_gossip": 3,
        "seen_ttl_secs": 120,
    }
    defaults.update(overrides)
    return GossipsubParameters(**defaults)  # type: ignore[arg-type]


@pytest.fixture
async def network() -> AsyncGenerator[GossipsubTestNetwork]:
    """Provide a test network with automatic teardown.

    Teardown stops all nodes, cancelling background tasks and closing
    streams. This prevents leaked coroutines between tests.
    """
    net = GossipsubTestNetwork()
    yield net
    try:
        await asyncio.wait_for(net.stop_all(), timeout=10.0)
    except asyncio.TimeoutError:
        pass


@pytest.fixture
async def two_nodes(
    network: GossipsubTestNetwork,
) -> tuple[GossipsubTestNode, GossipsubTestNode]:
    """Two connected nodes with fast parameters."""
    nodes = await network.create_nodes(2, fast_params())
    await network.start_all()
    await nodes[0].connect_to(nodes[1])
    return nodes[0], nodes[1]
