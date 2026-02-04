"""
Port allocation for interop test nodes.

Provides thread-safe allocation of network ports for test nodes.
Each test run gets unique ports to avoid conflicts.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

BASE_P2P_PORT = 20600
"""Starting port for P2P (libp2p) connections."""

BASE_API_PORT = 16652
"""Starting port for HTTP API servers."""


@dataclass(slots=True)
class PortAllocator:
    """
    Thread-safe port allocator for test nodes.

    Allocates sequential port ranges for P2P and API servers.
    Each node gets a unique pair of ports.
    """

    _p2p_counter: int = field(default=0)
    """Current P2P port offset."""

    _api_counter: int = field(default=0)
    """Current API port offset."""

    _lock: threading.Lock = field(default_factory=threading.Lock)
    """Thread lock for concurrent access."""

    def allocate_p2p_port(self) -> int:
        """
        Allocate a P2P port.

        Returns:
            Unique P2P port number.
        """
        with self._lock:
            port = BASE_P2P_PORT + self._p2p_counter
            self._p2p_counter += 1
            return port

    def allocate_api_port(self) -> int:
        """
        Allocate an API port.

        Returns:
            Unique API port number.
        """
        with self._lock:
            port = BASE_API_PORT + self._api_counter
            self._api_counter += 1
            return port

    def allocate_ports(self) -> tuple[int, int]:
        """
        Allocate both P2P and API ports for a node.

        Returns:
            Tuple of (p2p_port, api_port).
        """
        with self._lock:
            p2p_port = BASE_P2P_PORT + self._p2p_counter
            api_port = BASE_API_PORT + self._api_counter
            self._p2p_counter += 1
            self._api_counter += 1
            return p2p_port, api_port

    def reset(self) -> None:
        """Reset counters to initial state."""
        with self._lock:
            self._p2p_counter = 0
            self._api_counter = 0
