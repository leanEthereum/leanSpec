"""
Network topology patterns for interop tests.

Each pattern returns a list of (dialer_index, listener_index) pairs
representing which nodes should connect to which.
"""

from __future__ import annotations


def full_mesh(n: int) -> list[tuple[int, int]]:
    """
    Every node connects to every other node.

    Creates n*(n-1)/2 connections total.

    Args:
        n: Number of nodes.

    Returns:
        List of (dialer, listener) index pairs.
    """
    connections: list[tuple[int, int]] = []
    for i in range(n):
        # Only connect i -> j where i < j to avoid duplicate bidirectional connections.
        # libp2p connections are bidirectional, so (0,1) also gives (1,0).
        for j in range(i + 1, n):
            connections.append((i, j))
    return connections
