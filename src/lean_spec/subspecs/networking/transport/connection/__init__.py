"""
Connection management for libp2p transport.

This module provides the QUIC-based connection types which handle the full
transport stack. QUIC provides encryption (TLS 1.3) and multiplexing natively,
eliminating the need for separate encryption and multiplexing layers.

Exports:
    - Connection, Stream: Protocol classes for type annotations
    - ConnectionManager: QuicConnectionManager for actual use
    - QuicConnection, QuicStream: Concrete implementations
"""

from ..quic.connection import QuicConnection, QuicStream
from ..quic.connection import QuicConnectionManager as ConnectionManager
from .types import Connection, Stream

__all__ = [
    "Connection",
    "Stream",
    "ConnectionManager",
    "QuicConnection",
    "QuicStream",
]
