"""
Shared Protocol definitions for transport layer.

These protocols define the interface for stream-like objects used
throughout the networking transport stack. They allow the transport
code to work with asyncio streams, yamux streams, or any other
implementation that provides the same interface.
"""

from __future__ import annotations

from typing import Protocol


class StreamReaderProtocol(Protocol):
    """Protocol for objects that can read data like asyncio.StreamReader."""

    async def read(self, n: int) -> bytes:
        """Read up to n bytes."""
        ...

    async def readexactly(self, n: int) -> bytes:
        """Read exactly n bytes."""
        ...


class StreamWriterProtocol(Protocol):
    """Protocol for objects that can write data like asyncio.StreamWriter."""

    def write(self, data: bytes) -> None:
        """Write data to buffer."""
        ...

    async def drain(self) -> None:
        """Flush the buffer."""
        ...

    def close(self) -> None:
        """Close the writer."""
        ...

    async def wait_closed(self) -> None:
        """Wait for the writer to close."""
        ...
