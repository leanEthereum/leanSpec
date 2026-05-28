"""In-memory bidirectional stream pair for integration testing.

Provides the same interface as QuicStreamAdapter (read, write, drain, close)
so GossipsubBehavior can exchange RPCs without a real QUIC transport.
"""

from __future__ import annotations

import asyncio


class InMemoryStream:
    """Async bidirectional stream backed by asyncio.Queue.

    Matches the QuicStreamAdapter interface used by GossipsubBehavior:

    - write() buffers data synchronously
    - drain() flushes the buffer into the peer's read queue
    - read() returns data from our read queue
    - close() signals EOF to the peer

    The sync-write/async-drain split mirrors how QUIC streams work.
    Application code builds a message with one or more sync writes,
    then a single async drain pushes the whole buffer to the peer.
    """

    def __init__(
        self,
        read_queue: asyncio.Queue[bytes],
        peer_queue: asyncio.Queue[bytes],
    ) -> None:
        self._read_queue = read_queue
        self._peer_queue = peer_queue
        self._write_buffer = b""
        self._closed = False
        self._read_buffer = b""

    async def read(self, n: int | None = None) -> bytes:
        """Read bytes from the stream.

        Returns data from the internal read queue. An empty bytes
        object signals EOF (peer closed their end).
        """
        if self._closed and not self._read_buffer:
            return b""

        # Return from leftover buffer first.
        #
        # A previous read may have fetched more bytes than requested.
        # Serve those before waiting on the queue again.
        if self._read_buffer:
            if n is None:
                result = self._read_buffer
                self._read_buffer = b""
                return result
            result = self._read_buffer[:n]
            self._read_buffer = self._read_buffer[n:]
            return result

        try:
            data = await self._read_queue.get()
        except asyncio.CancelledError:
            return b""

        # Empty bytes is the EOF sentinel from the peer's close().
        if not data:
            self._closed = True
            return b""

        # Store excess bytes for the next read call.
        if n is not None and len(data) > n:
            self._read_buffer = data[n:]
            return data[:n]
        return data

    async def readexactly(self, n: int) -> bytes:
        """Read exactly n bytes. Raises EOFError if stream closes early."""
        result = b""
        while len(result) < n:
            chunk = await self.read(n - len(result))
            if not chunk:
                raise EOFError("Stream closed before enough data received")
            result += chunk
        return result

    def write(self, data: bytes) -> None:
        """Buffer data for writing (synchronous)."""
        self._write_buffer += data

    async def drain(self) -> None:
        """Flush buffered data into the peer's read queue."""
        if self._write_buffer:
            await self._peer_queue.put(self._write_buffer)
            self._write_buffer = b""

    async def close(self) -> None:
        """Signal EOF to the peer by sending an empty sentinel.

        An empty bytes object travels through the same queue as data.
        This guarantees the peer processes all prior writes before seeing EOF.
        """
        await self._peer_queue.put(b"")
        self._closed = True


def create_stream_pair() -> tuple[InMemoryStream, InMemoryStream]:
    """Create a pair of connected in-memory streams.

    Returns (stream_a, stream_b) where:
    - Writing to stream_a is readable from stream_b
    - Writing to stream_b is readable from stream_a
    """
    # Two queues form the bidirectional channel.
    # Each stream reads from one queue and writes to the other.
    # The cross-wiring below makes A's writes arrive at B's reads and vice versa.
    q_a_to_b: asyncio.Queue[bytes] = asyncio.Queue()
    q_b_to_a: asyncio.Queue[bytes] = asyncio.Queue()

    stream_a = InMemoryStream(read_queue=q_b_to_a, peer_queue=q_a_to_b)
    stream_b = InMemoryStream(read_queue=q_a_to_b, peer_queue=q_b_to_a)

    return stream_a, stream_b
