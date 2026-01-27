"""
Mock classes for testing transport and networking layers.

Each mock provides minimal implementations for isolated testing.
"""

from __future__ import annotations


class MockNoiseSession:
    """
    Mock NoiseSession for testing yamux multiplexing.

    Tracks written data and provides configurable read responses.
    Does not perform actual encryption or handshake.
    """

    def __init__(self) -> None:
        """Initialize with empty buffers."""
        self._written: list[bytes] = []
        self._to_read: list[bytes] = []
        self._closed = False

    @property
    def written(self) -> list[bytes]:
        """Data written through this session."""
        return self._written

    @property
    def is_closed(self) -> bool:
        """Whether the session has been closed."""
        return self._closed

    def queue_read(self, data: bytes) -> None:
        """
        Queue data to be returned by the next read call.

        Multiple calls queue data in FIFO order.
        """
        self._to_read.append(data)

    async def write(self, plaintext: bytes) -> None:
        """Record written data for later inspection."""
        self._written.append(plaintext)

    async def read(self) -> bytes:
        """
        Return queued data or empty bytes.

        Consumes queued data in FIFO order.
        """
        if self._to_read:
            return self._to_read.pop(0)
        return b""

    async def close(self) -> None:
        """Mark the session as closed."""
        self._closed = True
