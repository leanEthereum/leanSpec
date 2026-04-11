r"""Buffered read/write adapter for QuicStream with multistream-select negotiation.

QuicStream provides raw, unbuffered I/O — each read returns exactly one
QUIC frame's worth of data. Higher-level protocols (multistream-select,
gossipsub RPC framing, req/resp) need buffered reads with exact byte counts
and length-prefixed writes. This adapter bridges those two interfaces.

Negotiation is built in because every QUIC stream uses multistream-select
before any application data flows. Keeping it here avoids the duplicate
reader/writer argument pattern that standalone functions required.

Wire format:
    Message = [varint length][payload + '\n']
    - Length is encoded as unsigned LEB128 varint
    - Length INCLUDES the trailing newline
    - Maximum message size: 1024 bytes (arbitrary but reasonable)

Protocol flow:
    1. Both sides send the multistream header: /multistream/1.0.0
    2. Client proposes a protocol
    3. Server either echoes (accept) or sends "na" (reject)
    4. If rejected, client can propose another protocol
    5. On acceptance, negotiation is complete

References:
    - https://github.com/multiformats/multistream-select
"""

from __future__ import annotations

import asyncio
from typing import Final

from lean_spec.subspecs.networking.types import ProtocolId
from lean_spec.subspecs.networking.varint import decode_varint, encode_varint

from .stream import QuicStream

MULTISTREAM_PROTOCOL_ID: Final[str] = "/multistream/1.0.0"
"""Protocol identifier for multistream-select 1.0."""

NA: Final[str] = "na"
"""Rejection response sent when protocol is not supported."""

MAX_MESSAGE_SIZE: Final[int] = 1024
"""Maximum message size (arbitrary but reasonable)."""

MAX_NEGOTIATION_ATTEMPTS: Final[int] = 10
"""Maximum protocol proposals before giving up."""

DEFAULT_TIMEOUT: Final[float] = 30.0
"""Default timeout for negotiation (seconds)."""


class NegotiationError(Exception):
    """Raised when protocol negotiation fails."""


class QuicStreamAdapter:
    """Adapts QuicStream for buffered, protocol-level I/O.

    Provides:

    - Buffered reads: ``read(n)`` returns exactly up to *n* bytes,
      keeping leftovers for the next call.
    - Exact reads: ``readexactly(n)`` blocks until *n* bytes arrive.
    - Buffered writes: ``write()`` accumulates data, ``drain()`` flushes.
    - Half-close: ``finish_write()`` flushes then sends FIN.
    - Multistream-select negotiation via ``negotiate_*`` methods.
    """

    __slots__ = ("_stream", "_buffer", "_write_buffer")

    def __init__(self, stream: QuicStream) -> None:
        """Initialize the adapter wrapping the given QUIC stream."""
        self._stream = stream
        self._buffer = b""
        self._write_buffer = b""

    async def read(self, n: int | None = None) -> bytes:
        """Read bytes from the stream.

        - If *n* is provided, returns at most *n* bytes.
        - If *n* is None, returns all available data (no limit).

        Returns from internal buffer first, then reads from the stream.
        """
        if n is None:
            if self._buffer:
                result = self._buffer
                self._buffer = b""
                return result
            return await self._stream.read()

        if self._buffer:
            result = self._buffer[:n]
            self._buffer = self._buffer[n:]
            return result

        data = await self._stream.read()
        if not data:
            return b""

        if len(data) > n:
            self._buffer = data[n:]
            return data[:n]
        return data

    async def readexactly(self, n: int) -> bytes:
        """Read exactly *n* bytes from the stream.

        Raises:
            EOFError: If the stream closes before *n* bytes arrive.
        """
        while len(self._buffer) < n:
            chunk = await self._stream.read()
            if not chunk:
                raise EOFError("Stream closed before enough data received")
            self._buffer += chunk

        result = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return result

    def write(self, data: bytes) -> None:
        """Buffer data for writing (synchronous for StreamWriter compatibility)."""
        self._write_buffer += data

    async def drain(self) -> None:
        """Flush buffered data to the stream."""
        if self._write_buffer:
            await self._stream.write(self._write_buffer)
            self._write_buffer = b""

    async def close(self) -> None:
        """Close the underlying stream."""
        await self._stream.close()

    async def finish_write(self) -> None:
        """Half-close the stream (signal end of writing).

        Flushes any buffered data before sending FIN.
        """
        if self._write_buffer:
            await self._stream.write(self._write_buffer)
            self._write_buffer = b""
        await self._stream.finish_write()

    async def negotiate_client(self, protocols: list[ProtocolId]) -> ProtocolId:
        """Client-side protocol negotiation.

        Proposes protocols in order until one is accepted.

        Args:
            protocols: Protocols to propose, in preference order.

        Returns:
            The accepted protocol ID.

        Raises:
            NegotiationError: If no protocol is accepted or protocol error.
        """
        if not protocols:
            raise NegotiationError("No protocols to negotiate")

        # Exchange multistream headers.
        await self._write_negotiation_message(MULTISTREAM_PROTOCOL_ID)
        header = await self._read_negotiation_message()

        if header != MULTISTREAM_PROTOCOL_ID:
            raise NegotiationError(f"Invalid multistream header: {header!r}")

        # Try each protocol in order.
        for protocol in protocols:
            await self._write_negotiation_message(protocol)
            response = await self._read_negotiation_message()

            if response == protocol:
                return protocol
            elif response == NA:
                continue
            else:
                raise NegotiationError(f"Unexpected response: {response!r}")

        raise NegotiationError(f"No protocols accepted from: {protocols}")

    async def negotiate_server(
        self,
        supported: set[ProtocolId],
        timeout: float = DEFAULT_TIMEOUT,
    ) -> ProtocolId:
        """Server-side protocol negotiation.

        Waits for client to propose protocols, accepts first supported one.

        Args:
            supported: Set of protocol IDs this server supports.
            timeout: Maximum time to wait for negotiation (default 30s).

        Returns:
            The negotiated protocol ID.

        Raises:
            NegotiationError: If client proposes no supported protocols,
                too many attempts, or timeout reached.
        """
        if not supported:
            raise NegotiationError("No supported protocols")

        async def _do_negotiation() -> ProtocolId:
            header = await self._read_negotiation_message()

            if header != MULTISTREAM_PROTOCOL_ID:
                raise NegotiationError(f"Invalid multistream header: {header!r}")

            await self._write_negotiation_message(MULTISTREAM_PROTOCOL_ID)

            for _ in range(MAX_NEGOTIATION_ATTEMPTS):
                proposal = ProtocolId(await self._read_negotiation_message())

                if proposal in supported:
                    await self._write_negotiation_message(proposal)
                    return proposal
                else:
                    await self._write_negotiation_message(NA)

            raise NegotiationError(f"Too many negotiation attempts (>{MAX_NEGOTIATION_ATTEMPTS})")

        try:
            return await asyncio.wait_for(_do_negotiation(), timeout=timeout)
        except asyncio.TimeoutError:
            raise NegotiationError(f"Negotiation timed out after {timeout}s") from None

    async def negotiate_lazy_client(self, protocol: ProtocolId) -> ProtocolId:
        """Lazy client-side negotiation for single protocol.

        Sends both the multistream header and protocol proposal together,
        then waits for server to accept. Reduces round trips when we only
        want one specific protocol.

        Args:
            protocol: The protocol to propose.

        Returns:
            The accepted protocol (same as input if successful).

        Raises:
            NegotiationError: If protocol not accepted.
        """
        # Send header and protocol in one burst.
        await self._write_negotiation_message(MULTISTREAM_PROTOCOL_ID)
        await self._write_negotiation_message(protocol)

        header = await self._read_negotiation_message()
        if header != MULTISTREAM_PROTOCOL_ID:
            raise NegotiationError(f"Invalid multistream header: {header!r}")

        response = await self._read_negotiation_message()
        if response == protocol:
            return protocol
        elif response == NA:
            raise NegotiationError(f"Protocol rejected: {protocol}")
        else:
            raise NegotiationError(f"Unexpected response: {response!r}")

    async def _write_negotiation_message(self, message: str) -> None:
        r"""Write a multistream message.

        Format: [varint length][message + '\n']
        """
        payload = message.encode("utf-8") + b"\n"
        length_prefix = encode_varint(len(payload))
        self.write(length_prefix + payload)
        await self.drain()

    async def _read_negotiation_message(self) -> str:
        """Read a multistream message.

        Returns:
            Message content (without newline).

        Raises:
            NegotiationError: If message is malformed.
        """
        # Read length varint byte by byte.
        length_bytes = bytearray()
        while True:
            byte = await self.read(1)
            if not byte:
                raise NegotiationError("Connection closed while reading length")

            length_bytes.append(byte[0])

            if byte[0] & 0x80 == 0:
                break

            if len(length_bytes) > 5:
                raise NegotiationError("Varint too long")

        try:
            length, _ = decode_varint(bytes(length_bytes))
        except Exception as e:
            raise NegotiationError(f"Invalid varint: {e}") from e

        if length > MAX_MESSAGE_SIZE:
            raise NegotiationError(f"Message too large: {length}")

        if length == 0:
            raise NegotiationError("Empty message")

        payload = await self.readexactly(length)

        if not payload.endswith(b"\n"):
            raise NegotiationError("Message must end with newline")

        return payload[:-1].decode("utf-8")
