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


@dataclass(slots=True)
class PortAllocator:
    """
    Thread-safe port allocator for test nodes.

    Allocates sequential P2P ports starting from the base port.
    Each node gets a unique port.
    """

    _counter: int = field(default=0)
    """Number of ports allocated so far."""

    _lock: threading.Lock = field(default_factory=threading.Lock)
    """Thread lock for concurrent access."""

    def allocate_port(self) -> int:
        """
        Allocate a unique P2P port.

        Returns:
            Port number, sequential from BASE_P2P_PORT.
        """
        # Serialize access so parallel test setup cannot allocate the same port.
        with self._lock:
            port = BASE_P2P_PORT + self._counter
            self._counter += 1
            return port
