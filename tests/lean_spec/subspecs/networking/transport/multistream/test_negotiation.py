"""
Tests for multistream-select 1.0 protocol negotiation.

Wire format:
    Message = [varint length][payload + '\\n']
    - Length includes the trailing newline
    - Maximum message size: 1024 bytes

Protocol flow:
    1. Both sides send multistream header: /multistream/1.0.0
    2. Client proposes a protocol
    3. Server echoes (accept) or sends "na" (reject)

Reference: https://github.com/multiformats/multistream-select
"""

from __future__ import annotations

import asyncio

import pytest

from lean_spec.subspecs.networking.transport.multistream import (
    MULTISTREAM_PROTOCOL_ID,
    NA,
    NegotiationError,
    negotiate_client,
    negotiate_lazy_client,
    negotiate_server,
)
from lean_spec.subspecs.networking.transport.multistream.negotiation import (
    StreamReaderProtocol,
    StreamWriterProtocol,
)


class TestConstants:
    """Tests for protocol constants."""

    def test_protocol_id(self) -> None:
        """Protocol ID matches spec."""
        assert MULTISTREAM_PROTOCOL_ID == "/multistream/1.0.0"

    def test_na_constant(self) -> None:
        """NA rejection string."""
        assert NA == "na"


class TestNegotiateClient:
    """Tests for client-side negotiation."""

    def test_client_accepts_first_protocol(self) -> None:
        """Client successfully negotiates first proposed protocol."""

        async def run_test() -> str:
            # Simulate server that accepts /noise
            client_reader, server_writer = _create_pipe()
            server_reader, client_writer = _create_pipe()

            async def server_task() -> None:
                # Server reads header and echoes
                await _read_message(server_reader)
                await _write_message(server_writer, MULTISTREAM_PROTOCOL_ID)
                # Server reads proposal and accepts
                protocol = await _read_message(server_reader)
                await _write_message(server_writer, protocol)

            # Run server in background
            server = asyncio.create_task(server_task())

            # Client negotiates
            result = await negotiate_client(client_reader, client_writer, ["/noise"])

            await server
            return result

        result = asyncio.run(run_test())
        assert result == "/noise"

    def test_client_tries_multiple_protocols(self) -> None:
        """Client tries protocols until one is accepted."""

        async def run_test() -> str:
            client_reader, server_writer = _create_pipe()
            server_reader, client_writer = _create_pipe()

            async def server_task() -> None:
                # Header exchange
                await _read_message(server_reader)
                await _write_message(server_writer, MULTISTREAM_PROTOCOL_ID)
                # Reject first protocol
                await _read_message(server_reader)  # /yamux
                await _write_message(server_writer, NA)
                # Accept second protocol
                protocol = await _read_message(server_reader)  # /mplex
                await _write_message(server_writer, protocol)

            server = asyncio.create_task(server_task())

            result = await negotiate_client(
                client_reader,
                client_writer,
                ["/yamux/1.0.0", "/mplex/6.7.0"],
            )

            await server
            return result

        result = asyncio.run(run_test())
        assert result == "/mplex/6.7.0"

    def test_client_all_rejected(self) -> None:
        """Client raises error when all protocols rejected."""

        async def run_test() -> None:
            client_reader, server_writer = _create_pipe()
            server_reader, client_writer = _create_pipe()

            async def server_task() -> None:
                # Header exchange
                await _read_message(server_reader)
                await _write_message(server_writer, MULTISTREAM_PROTOCOL_ID)
                # Reject all protocols
                await _read_message(server_reader)
                await _write_message(server_writer, NA)
                await _read_message(server_reader)
                await _write_message(server_writer, NA)

            server = asyncio.create_task(server_task())

            with pytest.raises(NegotiationError, match="No protocols accepted"):
                await negotiate_client(
                    client_reader,
                    client_writer,
                    ["/proto1", "/proto2"],
                )

            await server

        asyncio.run(run_test())

    def test_client_empty_protocols(self) -> None:
        """Client raises error when no protocols provided."""

        async def run_test() -> None:
            reader = asyncio.StreamReader()
            writer = _MockWriter()

            with pytest.raises(NegotiationError, match="No protocols to negotiate"):
                await negotiate_client(reader, writer, [])

        asyncio.run(run_test())

    def test_client_invalid_header(self) -> None:
        """Client raises error on invalid header."""

        async def run_test() -> None:
            client_reader, server_writer = _create_pipe()
            _, client_writer = _create_pipe()

            # Server sends wrong header
            await _write_message(server_writer, "/wrong/1.0.0")

            with pytest.raises(NegotiationError, match="Invalid multistream header"):
                await negotiate_client(client_reader, client_writer, ["/noise"])

        asyncio.run(run_test())


class TestNegotiateServer:
    """Tests for server-side negotiation."""

    def test_server_accepts_supported_protocol(self) -> None:
        """Server accepts protocol it supports."""

        async def run_test() -> str:
            server_reader, client_writer = _create_pipe()
            client_reader, server_writer = _create_pipe()

            async def client_task() -> None:
                # Client sends header
                await _write_message(client_writer, MULTISTREAM_PROTOCOL_ID)
                # Client reads header
                await _read_message(client_reader)
                # Client proposes protocol
                await _write_message(client_writer, "/noise")
                # Client reads response
                await _read_message(client_reader)

            client = asyncio.create_task(client_task())

            result = await negotiate_server(
                server_reader,
                server_writer,
                {"/noise", "/mplex/6.7.0"},
            )

            await client
            return result

        result = asyncio.run(run_test())
        assert result == "/noise"

    def test_server_rejects_unsupported_then_accepts(self) -> None:
        """Server rejects unsupported protocols."""

        async def run_test() -> str:
            server_reader, client_writer = _create_pipe()
            client_reader, server_writer = _create_pipe()

            async def client_task() -> None:
                # Header exchange
                await _write_message(client_writer, MULTISTREAM_PROTOCOL_ID)
                await _read_message(client_reader)
                # First proposal (unsupported)
                await _write_message(client_writer, "/yamux/1.0.0")
                response1 = await _read_message(client_reader)
                assert response1 == NA
                # Second proposal (supported)
                await _write_message(client_writer, "/mplex/6.7.0")
                response2 = await _read_message(client_reader)
                assert response2 == "/mplex/6.7.0"

            client = asyncio.create_task(client_task())

            result = await negotiate_server(
                server_reader,
                server_writer,
                {"/mplex/6.7.0"},  # Only mplex supported
            )

            await client
            return result

        result = asyncio.run(run_test())
        assert result == "/mplex/6.7.0"

    def test_server_empty_supported(self) -> None:
        """Server raises error when no supported protocols."""

        async def run_test() -> None:
            reader = asyncio.StreamReader()
            writer = _MockWriter()

            with pytest.raises(NegotiationError, match="No supported protocols"):
                await negotiate_server(reader, writer, set())

        asyncio.run(run_test())

    def test_server_invalid_header(self) -> None:
        """Server raises error on invalid client header."""

        async def run_test() -> None:
            server_reader, client_writer = _create_pipe()
            _, server_writer = _create_pipe()

            # Client sends wrong header
            await _write_message(client_writer, "/wrong/1.0.0")

            with pytest.raises(NegotiationError, match="Invalid multistream header"):
                await negotiate_server(server_reader, server_writer, {"/noise"})

        asyncio.run(run_test())


class TestLazyClient:
    """Tests for lazy client negotiation."""

    def test_lazy_client_single_protocol(self) -> None:
        """Lazy client sends header and proposal together."""

        async def run_test() -> str:
            client_reader, server_writer = _create_pipe()
            server_reader, client_writer = _create_pipe()

            async def server_task() -> None:
                # Server can read header and proposal (sent together)
                header = await _read_message(server_reader)
                assert header == MULTISTREAM_PROTOCOL_ID
                protocol = await _read_message(server_reader)
                assert protocol == "/noise"

                # Server responds
                await _write_message(server_writer, MULTISTREAM_PROTOCOL_ID)
                await _write_message(server_writer, protocol)

            server = asyncio.create_task(server_task())

            result = await negotiate_lazy_client(client_reader, client_writer, "/noise")

            await server
            return result

        result = asyncio.run(run_test())
        assert result == "/noise"

    def test_lazy_client_rejected(self) -> None:
        """Lazy client raises error when protocol rejected."""

        async def run_test() -> None:
            client_reader, server_writer = _create_pipe()
            server_reader, client_writer = _create_pipe()

            async def server_task() -> None:
                await _read_message(server_reader)  # header
                await _read_message(server_reader)  # protocol
                await _write_message(server_writer, MULTISTREAM_PROTOCOL_ID)
                await _write_message(server_writer, NA)  # reject

            server = asyncio.create_task(server_task())

            with pytest.raises(NegotiationError, match="Protocol rejected"):
                await negotiate_lazy_client(client_reader, client_writer, "/unsupported")

            await server

        asyncio.run(run_test())

    def test_lazy_client_invalid_header(self) -> None:
        """Lazy client raises error on invalid server header."""

        async def run_test() -> None:
            client_reader, server_writer = _create_pipe()
            _, client_writer = _create_pipe()

            await _write_message(server_writer, "/wrong/1.0.0")

            with pytest.raises(NegotiationError, match="Invalid multistream header"):
                await negotiate_lazy_client(client_reader, client_writer, "/noise")

        asyncio.run(run_test())


class TestMessageFormat:
    """Tests for wire message format."""

    def test_message_format(self) -> None:
        """Messages are length-prefixed with trailing newline."""

        async def run_test() -> bytes:
            reader, writer = _create_pipe()

            await _write_message(writer, "/noise")

            # Read raw bytes to verify format
            return await reader.read(100)

        raw = asyncio.run(run_test())

        # Length prefix (varint) + "/noise\n"
        # 7 bytes total for "/noise\n", varint(7) = 0x07
        assert raw[0] == 7
        assert raw[1:] == b"/noise\n"

    def test_message_roundtrip(self) -> None:
        """Write then read returns original message."""

        async def run_test() -> str:
            reader, writer = _create_pipe()

            original = "/test/protocol/1.0.0"
            await _write_message(writer, original)
            return await _read_message(reader)

        received = asyncio.run(run_test())
        assert received == "/test/protocol/1.0.0"


class TestFullNegotiation:
    """Integration tests for full negotiation scenarios."""

    def test_bidirectional_negotiation(self) -> None:
        """Client and server negotiate successfully."""

        async def run_test() -> tuple[str, str]:
            # Create bidirectional pipes
            client_reader, server_writer = _create_pipe()
            server_reader, client_writer = _create_pipe()

            async def client_task() -> str:
                return await negotiate_client(
                    client_reader,
                    client_writer,
                    ["/noise", "/mplex/6.7.0"],
                )

            async def server_task() -> str:
                return await negotiate_server(
                    server_reader,
                    server_writer,
                    {"/noise", "/yamux/1.0.0"},
                )

            return await asyncio.gather(
                client_task(),
                server_task(),
            )

        client_result, server_result = asyncio.run(run_test())

        assert client_result == "/noise"
        assert server_result == "/noise"

    def test_negotiate_yamux(self) -> None:
        """Negotiate yamux protocol."""

        async def run_test() -> tuple[str, str]:
            client_reader, server_writer = _create_pipe()
            server_reader, client_writer = _create_pipe()

            async def client_task() -> str:
                return await negotiate_client(
                    client_reader,
                    client_writer,
                    ["/yamux/1.0.0"],
                )

            async def server_task() -> str:
                return await negotiate_server(
                    server_reader,
                    server_writer,
                    {"/yamux/1.0.0"},
                )

            return await asyncio.gather(
                client_task(),
                server_task(),
            )

        client_result, server_result = asyncio.run(run_test())

        assert client_result == "/yamux/1.0.0"
        assert server_result == "/yamux/1.0.0"

    def test_negotiate_with_fallback(self) -> None:
        """Client falls back to second option when first rejected."""

        async def run_test() -> tuple[str, str]:
            client_reader, server_writer = _create_pipe()
            server_reader, client_writer = _create_pipe()

            async def client_task() -> str:
                return await negotiate_client(
                    client_reader,
                    client_writer,
                    ["/yamux/1.0.0", "/mplex/6.7.0"],  # yamux first
                )

            async def server_task() -> str:
                return await negotiate_server(
                    server_reader,
                    server_writer,
                    {"/mplex/6.7.0"},  # only mplex
                )

            return await asyncio.gather(
                client_task(),
                server_task(),
            )

        client_result, server_result = asyncio.run(run_test())

        # Both agree on mplex
        assert client_result == "/mplex/6.7.0"
        assert server_result == "/mplex/6.7.0"


# Helper functions for testing


def _create_pipe() -> tuple[StreamReaderProtocol, StreamWriterProtocol]:
    """Create a connected reader/writer pair for testing."""
    reader = asyncio.StreamReader()
    writer = _MockWriter(reader)
    return reader, writer


class _MockWriter:
    """Mock StreamWriter that writes to a StreamReader."""

    def __init__(self, reader: asyncio.StreamReader | None = None) -> None:
        self._reader = reader or asyncio.StreamReader()

    def write(self, data: bytes) -> None:
        """Write data to the connected reader."""
        self._reader.feed_data(data)

    async def drain(self) -> None:
        """No-op drain."""
        pass

    def close(self) -> None:
        """Close the writer."""
        if self._reader:
            self._reader.feed_eof()

    async def wait_closed(self) -> None:
        """No-op wait."""
        pass


async def _write_message(writer: StreamWriterProtocol, message: str) -> None:
    """Write a multistream message."""
    from lean_spec.subspecs.networking.varint import encode as encode_varint

    payload = message.encode("utf-8") + b"\n"
    length_prefix = encode_varint(len(payload))
    writer.write(length_prefix + payload)
    await writer.drain()


async def _read_message(reader: StreamReaderProtocol) -> str:
    """Read a multistream message."""
    # Read length varint byte by byte
    length_bytes = bytearray()
    while True:
        byte = await reader.read(1)
        if not byte:
            raise NegotiationError("Connection closed")
        length_bytes.append(byte[0])
        if byte[0] & 0x80 == 0:
            break

    from lean_spec.subspecs.networking.varint import decode as decode_varint

    length, _ = decode_varint(bytes(length_bytes))

    # Read payload
    payload = await reader.readexactly(length)

    # Strip trailing newline
    if not payload.endswith(b"\n"):
        raise NegotiationError("Message must end with newline")

    return payload[:-1].decode("utf-8")
