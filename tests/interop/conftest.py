"""
Shared pytest fixtures for interop tests.

Provides node cluster fixtures with automatic cleanup.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator

import pytest

from .helpers import NodeCluster, PortAllocator

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@pytest.fixture(scope="session")
def port_allocator() -> PortAllocator:
    """
    Provide a shared port allocator across all tests.

    Session-scoped to prevent port conflicts from TIME_WAIT state.
    Each test gets unique ports that don't overlap.
    """
    return PortAllocator()


@pytest.fixture
async def node_cluster(
    request: pytest.FixtureRequest,
    port_allocator: PortAllocator,
) -> AsyncGenerator[NodeCluster, None]:
    """
    Provide a node cluster with automatic cleanup.

    Validator count is configurable via the ``num_validators`` marker.
    Default: 3 validators.
    """
    marker = request.node.get_closest_marker("num_validators")
    num_validators = marker.args[0] if marker else 3

    cluster = NodeCluster(num_validators=num_validators, port_allocator=port_allocator)

    try:
        yield cluster
    finally:
        # Hard timeout on teardown to prevent QUIC listener cleanup hangs.
        # If graceful shutdown exceeds the budget, force-cancel remaining tasks.
        try:
            await asyncio.wait_for(cluster.stop_all(), timeout=10.0)
        except (asyncio.TimeoutError, Exception):
            logger.warning("Cluster teardown timed out, force-cancelling tasks")
            for node in cluster.nodes:
                for task in [node._task, node._listener_task]:
                    if task and not task.done():
                        task.cancel()
