"""
Connection management for libp2p transport.

This module provides the ConnectionManager which handles the full
TCP -> Noise -> yamux stack. It manages connection lifecycle including:

    1. TCP connect/accept
    2. multistream-select to negotiate /noise
    3. Noise XX handshake
    4. multistream-select to negotiate /yamux/1.0.0
    5. yamux session ready for application streams

The Connection and Stream protocols define abstract interfaces that
allow the transport layer to be used by leanSpec's networking code
without tight coupling.
"""

from .manager import ConnectionManager
from .types import Connection, Stream

__all__ = [
    "Connection",
    "Stream",
    "ConnectionManager",
]
