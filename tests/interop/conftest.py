"""
Shared pytest fixtures for interop tests.

Provides node cluster fixtures with automatic cleanup.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING

import pytest

from .helpers import NodeCluster, PortAllocator

if TYPE_CHECKING:
    pass

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

    Configure via pytest markers::

        @pytest.mark.num_validators(3)
        def test_example(node_cluster): ...

    Default: 3 validators.
    """
    marker = request.node.get_closest_marker("num_validators")
    num_validators = marker.args[0] if marker else 3

    cluster = NodeCluster(num_validators=num_validators, port_allocator=port_allocator)

    try:
        yield cluster
    finally:
        await cluster.stop_all()


@pytest.fixture
async def two_node_cluster(
    port_allocator: PortAllocator,
) -> AsyncGenerator[NodeCluster, None]:
    """Provide a two-node cluster with one validator each."""
    cluster = NodeCluster(num_validators=2, port_allocator=port_allocator)

    try:
        yield cluster
    finally:
        await cluster.stop_all()


@pytest.fixture
async def three_node_cluster(
    port_allocator: PortAllocator,
) -> AsyncGenerator[NodeCluster, None]:
    """Provide a three-node cluster with one validator each."""
    cluster = NodeCluster(num_validators=3, port_allocator=port_allocator)

    try:
        yield cluster
    finally:
        await cluster.stop_all()


@pytest.fixture
def event_loop_policy():
    """Use default event loop policy."""
    return asyncio.DefaultEventLoopPolicy()
