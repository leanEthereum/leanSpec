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
        for j in range(i + 1, n):
            connections.append((i, j))
    return connections


def star(n: int, hub: int = 0) -> list[tuple[int, int]]:
    """
    All nodes connect to a central hub node.

    Creates n-1 connections total.

    Args:
        n: Number of nodes.
        hub: Index of the hub node (default 0).

    Returns:
        List of (dialer, listener) index pairs.
    """
    connections: list[tuple[int, int]] = []
    for i in range(n):
        if i != hub:
            connections.append((i, hub))
    return connections


def chain(n: int) -> list[tuple[int, int]]:
    """
    Linear chain: 0 -> 1 -> 2 -> ... -> n-1.

    Creates n-1 connections total.

    Args:
        n: Number of nodes.

    Returns:
        List of (dialer, listener) index pairs.
    """
    return [(i, i + 1) for i in range(n - 1)]


def mesh_2_2_2() -> list[tuple[int, int]]:
    """
    Ream-compatible mesh topology.

    Mirrors Ream's topology: vec![vec![], vec![0], vec![0, 1]]

    - Node 0: bootnode (accepts connections)
    - Node 1: connects to node 0
    - Node 2: connects to both node 0 AND node 1

    This creates a full mesh::

        Node 0 <---> Node 1
          ^           ^
          |           |
          +---> Node 2 <---+

    Returns:
        List of (dialer, listener) index pairs.
    """
    return [(1, 0), (2, 0), (2, 1)]
