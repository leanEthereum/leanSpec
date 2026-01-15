"""
Abstract interfaces for connections and streams.

These Protocol classes define the interface that the transport layer
exposes to higher-level networking code. Using Protocols allows the
transport implementation to evolve without breaking consumers.

The runtime_checkable decorator allows isinstance() checks, which is
useful for validation and testing.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Stream(Protocol):
    """
    A multiplexed stream - one request/response conversation.

    Streams are the primary unit of communication. Each stream is
    bidirectional and can be independently read, written, and closed.

    Streams are lightweight - thousands can exist per connection.
    Each stream belongs to exactly one connection.

    Example usage:
        stream = await connection.open_stream("/leanconsensus/req/status/1/ssz_snappy")
        await stream.write(encode_request(status))
        response_bytes = await stream.read()
        await stream.close()
    """

    @property
    def protocol_id(self) -> str:
        """
        The negotiated protocol for this stream.

        Set during stream opening via multistream-select negotiation.
        Example: "/leanconsensus/req/status/1/ssz_snappy"
        """
        ...

    async def read(self, n: int = -1) -> bytes:
        """
        Read data from the stream.

        Args:
            n: Maximum bytes to read. -1 means read all available.

        Returns:
            Read data. May be less than n bytes if stream is closing.
            Empty bytes indicates stream EOF.

        Raises:
            ConnectionError: If stream was reset or connection failed.
        """
        ...

    async def write(self, data: bytes) -> None:
        """
        Write data to the stream.

        Args:
            data: Data to send.

        Raises:
            ConnectionError: If stream was closed or connection failed.
        """
        ...

    async def close(self) -> None:
        """
        Half-close the stream.

        Signals we won't send more data. The peer can still send.
        This is a graceful close - pending writes are flushed first.
        """
        ...

    async def reset(self) -> None:
        """
        Abort the stream immediately.

        Both directions are closed without flushing. Use for error
        cases where graceful close isn't needed.
        """
        ...


@runtime_checkable
class Connection(Protocol):
    """
    A secure, multiplexed connection to a peer.

    Connections wrap the full TCP -> Noise -> yamux stack. Once
    established, streams can be opened for different protocols.

    Example usage:
        connection = await transport.connect("/ip4/127.0.0.1/tcp/9000")
        stream = await connection.open_stream("/leanconsensus/req/status/1/ssz_snappy")
        # ... use stream ...
        await connection.close()
    """

    @property
    def peer_id(self) -> str:
        """
        Remote peer's ID.

        Derived from their public key during Noise handshake.
        Format: Base58-encoded multihash (e.g., "12D3KooW...")
        """
        ...

    @property
    def remote_addr(self) -> str:
        """
        Remote address in multiaddr format.

        Example: "/ip4/192.168.1.1/tcp/9000"
        """
        ...

    async def open_stream(self, protocol: str) -> Stream:
        """
        Open a new stream for the given protocol.

        Performs multistream-select negotiation before returning.

        Args:
            protocol: Protocol ID to negotiate (e.g., "/leanconsensus/req/status/1/ssz_snappy")

        Returns:
            Open stream ready for read/write.

        Raises:
            NegotiationError: If protocol not supported by peer.
            ConnectionError: If connection has failed.
        """
        ...

    async def close(self) -> None:
        """
        Close the connection gracefully.

        All streams are closed and the underlying TCP connection
        is terminated.
        """
        ...
