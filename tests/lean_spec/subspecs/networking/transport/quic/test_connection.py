"""
Tests for QUIC connection, stream, and multiaddr utilities.

Tests verify behavior against RFC 9000 (QUIC) and the libp2p-QUIC/multiaddr specs.
"""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lean_spec.subspecs.networking.config import LIBP2P_ALPN_PROTOCOL
from lean_spec.subspecs.networking.transport.peer_id import PeerId
from lean_spec.subspecs.networking.transport.quic.connection import (
    ConnectionTerminated,
    HandshakeCompleted,
    LibP2PQuicProtocol,
    QuicConnection,
    QuicConnectionManager,
    QuicStream,
    QuicStreamResetError,
    QuicTransportError,
    StreamDataReceived,
    StreamReset,
    is_quic_multiaddr,
    parse_multiaddr,
)
from lean_spec.subspecs.networking.types import ProtocolId

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def peer_a() -> PeerId:
    """Peer ID derived from the Base58 string 'peerA'."""
    return PeerId.from_base58("peerA")


@pytest.fixture
def mock_protocol() -> MagicMock:
    """Mock aioquic protocol with stream tracking and transmit."""
    protocol = MagicMock()
    protocol._quic = MagicMock()
    protocol._quic._streams = {}
    protocol.transmit = MagicMock()
    return protocol


@pytest.fixture
def quic_stream(mock_protocol: MagicMock) -> QuicStream:
    """A QuicStream backed by the mock protocol on stream ID 0."""
    return QuicStream(_protocol=mock_protocol, _stream_id=0)


@pytest.fixture
def quic_connection(mock_protocol: MagicMock, peer_a: PeerId) -> QuicConnection:
    """A QuicConnection backed by the mock protocol."""
    return QuicConnection(
        _protocol=mock_protocol,
        _peer_id=peer_a,
        _remote_addr="/ip4/127.0.0.1/udp/9000/quic-v1",
    )


# ---------------------------------------------------------------------------
# Multiaddr detection — per the multiaddr spec, protocol names are
# case-sensitive and always lowercase.
# ---------------------------------------------------------------------------


class TestIsQuicMultiaddr:
    """Tests for QUIC multiaddr detection per the multiaddr spec."""

    @pytest.mark.parametrize(
        ("multiaddr", "expected"),
        [
            # Valid QUIC multiaddrs (lowercase per spec)
            ("/ip4/127.0.0.1/udp/9000/quic-v1", True),
            ("/ip4/10.0.0.1/udp/4001/quic", True),
            ("/ip4/0.0.0.0/udp/9000/quic-v1/p2p/peerA", True),
            ("/ip6/::1/udp/9000/quic-v1", True),
            # Not QUIC
            ("/ip4/127.0.0.1/tcp/9000", False),
            ("/ip4/127.0.0.1/udp/9000", False),
            ("", False),
            # Uppercase is NOT valid per multiaddr spec — protocol names are
            # case-sensitive and defined in lowercase.
            ("/ip4/127.0.0.1/udp/9000/QUIC-V1", False),
            ("/ip4/127.0.0.1/udp/9000/QUIC", False),
            ("/ip4/127.0.0.1/udp/9000/Quic-V1", False),
        ],
        ids=[
            "quic-v1",
            "quic-legacy",
            "quic-v1-with-peer",
            "ipv6-quic-v1",
            "tcp-not-quic",
            "udp-only-not-quic",
            "empty-string",
            "uppercase-rejected",
            "uppercase-legacy-rejected",
            "mixed-case-rejected",
        ],
    )
    def test_detection(self, multiaddr: str, expected: bool) -> None:
        """Multiaddr is correctly classified as QUIC or non-QUIC."""
        assert is_quic_multiaddr(multiaddr) == expected


# ---------------------------------------------------------------------------
# Multiaddr parsing
# ---------------------------------------------------------------------------


class TestParseMultiaddr:
    """Tests for multiaddr parsing into components."""

    def test_standard_quic_v1(self) -> None:
        """Standard QUIC-v1 multiaddr yields host, port, transport, and no peer."""
        assert parse_multiaddr("/ip4/127.0.0.1/udp/9000/quic-v1") == (
            "127.0.0.1",
            9000,
            "quic",
            None,
        )

    def test_ipv6_quic_v1(self) -> None:
        """IPv6 QUIC multiaddr is parsed correctly per the libp2p-QUIC spec."""
        assert parse_multiaddr("/ip6/::1/udp/9000/quic-v1") == (
            "::1",
            9000,
            "quic",
            None,
        )

    def test_with_peer_id(self, peer_a: PeerId) -> None:
        """Multiaddr with p2p component includes the parsed peer ID."""
        host, port, transport, parsed_peer = parse_multiaddr(
            "/ip4/10.0.0.1/udp/4001/quic-v1/p2p/peerA"
        )
        assert (host, port, transport) == ("10.0.0.1", 4001, "quic")
        assert parsed_peer == peer_a

    def test_legacy_quic(self) -> None:
        """Legacy 'quic' tag is recognized as transport 'quic'."""
        assert parse_multiaddr("/ip4/192.168.1.1/udp/5000/quic") == (
            "192.168.1.1",
            5000,
            "quic",
            None,
        )

    def test_missing_host_raises(self) -> None:
        """Missing ip4/ip6 component raises ValueError."""
        with pytest.raises(ValueError, match=r"No host in multiaddr"):
            parse_multiaddr("/udp/9000/quic-v1")

    def test_missing_port_raises(self) -> None:
        """Missing udp component raises ValueError."""
        with pytest.raises(ValueError, match=r"No port in multiaddr"):
            parse_multiaddr("/ip4/127.0.0.1/quic-v1")

    def test_unknown_components_skipped(self) -> None:
        """Unknown protocol components are silently skipped."""
        assert parse_multiaddr("/ip4/127.0.0.1/unknown/foo/udp/9000/quic-v1") == (
            "127.0.0.1",
            9000,
            "quic",
            None,
        )

    def test_no_quic_tag_returns_none_transport(self) -> None:
        """Multiaddr without quic/quic-v1 component returns None transport."""
        host, port, transport, _ = parse_multiaddr("/ip4/10.0.0.1/udp/3000")
        assert (host, port, transport) == ("10.0.0.1", 3000, None)


# ---------------------------------------------------------------------------
# ALPN protocol — per the libp2p TLS spec
#
# https://github.com/libp2p/specs/blob/master/tls/tls.md
# "Endpoints MUST NOT send (and MUST NOT accept) any ALPN extension that
#  does not include "libp2p" as the ALPN protocol string."
# ---------------------------------------------------------------------------


class TestAlpnProtocol:
    """Verify the ALPN protocol value per the libp2p TLS spec."""

    def test_alpn_is_libp2p(self) -> None:
        """The ALPN value is 'libp2p' as mandated by the libp2p TLS spec.

        Spec reference (https://github.com/libp2p/specs/blob/master/tls/tls.md):
        the ALPN extension MUST include "libp2p" as the protocol string.
        """
        assert LIBP2P_ALPN_PROTOCOL == "libp2p"


# ---------------------------------------------------------------------------
# QuicStream — read behavior per RFC 9000 Section 3
#
# - Data arrives in order per-stream.
# - FIN (end_stream=True) signals graceful half-close — all data delivered.
# - RESET_STREAM signals abrupt termination — data may be lost.
# ---------------------------------------------------------------------------


class TestQuicStreamRead:
    """Tests for reading data from a QUIC stream."""

    async def test_read_returns_buffered_data(self, quic_stream: QuicStream) -> None:
        """Data placed in the buffer is returned by read."""
        quic_stream._receive_data(b"hello")
        assert await quic_stream.read() == b"hello"

    async def test_read_returns_empty_on_fin(self, quic_stream: QuicStream) -> None:
        """FIN (graceful half-close) causes read to return empty bytes."""
        quic_stream._receive_end()
        assert await quic_stream.read() == b""
        # Per RFC 9000, stream is in "Data Read" terminal state.
        assert await quic_stream.read() == b""

    async def test_read_preserves_order(self, quic_stream: QuicStream) -> None:
        """Per RFC 9000, QUIC delivers data in order within a stream."""
        quic_stream._receive_data(b"first")
        quic_stream._receive_data(b"second")
        assert await quic_stream.read() == b"first"
        assert await quic_stream.read() == b"second"

    async def test_read_data_then_fin(self, quic_stream: QuicStream) -> None:
        """Data followed by FIN returns all data, then signals end."""
        quic_stream._receive_data(b"payload")
        quic_stream._receive_end()
        assert await quic_stream.read() == b"payload"
        assert await quic_stream.read() == b""

    async def test_read_after_close_returns_empty(self, quic_stream: QuicStream) -> None:
        """Reading a closed stream returns empty immediately."""
        await quic_stream.close()
        assert await quic_stream.read() == b""


# ---------------------------------------------------------------------------
# QuicStream — RESET_STREAM handling per RFC 9000 Section 3.2
#
# RESET_STREAM is an error/abort, NOT a clean end-of-stream.
# Data may have been lost. The application must be notified.
# ---------------------------------------------------------------------------


class TestQuicStreamReset:
    """Tests for RESET_STREAM error propagation."""

    async def test_reset_raises_on_read(self, quic_stream: QuicStream) -> None:
        """After reset, read raises an error with the error code from the peer."""
        quic_stream._receive_reset(error_code=42)
        with pytest.raises(QuicStreamResetError) as exc_info:
            await quic_stream.read()
        assert exc_info.value.stream_id == 0
        assert exc_info.value.error_code == 42

    async def test_reset_after_data_raises_after_consuming(self, quic_stream: QuicStream) -> None:
        """Data buffered before reset is delivered, then reset error is raised."""
        quic_stream._receive_data(b"partial")
        quic_stream._receive_reset(error_code=7)
        # Buffered data is still returned.
        assert await quic_stream.read() == b"partial"
        # Next read surfaces the reset error.
        with pytest.raises(QuicStreamResetError) as exc_info:
            await quic_stream.read()
        assert exc_info.value.error_code == 7

    async def test_repeated_reads_after_reset_raise(self, quic_stream: QuicStream) -> None:
        """Subsequent reads after reset continue to raise."""
        quic_stream._receive_reset(error_code=0)
        with pytest.raises(QuicStreamResetError):
            await quic_stream.read()
        with pytest.raises(QuicStreamResetError):
            await quic_stream.read()

    def test_reset_error_is_subclass_of_transport_error(self) -> None:
        """Reset error inherits from the base transport error."""
        assert issubclass(QuicStreamResetError, QuicTransportError)


# ---------------------------------------------------------------------------
# QuicStream — write behavior per RFC 9000 Section 3
#
# After FIN is sent (or stream is closed), further writes must fail.
# ---------------------------------------------------------------------------


class TestQuicStreamWrite:
    """Tests for writing data to a QUIC stream."""

    async def test_write_sends_data_and_transmits(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Writing sends data to the QUIC layer and flushes pending frames."""
        await quic_stream.write(b"hello")
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"hello")
        mock_protocol.transmit.assert_called_once()

    async def test_write_after_fin_raises(self, quic_stream: QuicStream) -> None:
        """Per RFC 9000, no data can be sent after FIN (write-side closed)."""
        quic_stream._write_closed = True
        with pytest.raises(QuicTransportError, match=r"Stream write side is closed"):
            await quic_stream.write(b"data")


# ---------------------------------------------------------------------------
# QuicStream — half-close (FIN) per RFC 9000 Section 3
#
# Sending FIN closes the write side. Read side stays open.
# ---------------------------------------------------------------------------


class TestQuicStreamFinishWrite:
    """Tests for half-close via FIN."""

    async def test_finish_write_sends_fin(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Half-close sends a STREAM frame with FIN bit (end_stream=True)."""
        await quic_stream.finish_write()
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"", end_stream=True)
        mock_protocol.transmit.assert_called_once()
        assert quic_stream._write_closed is True
        # Read side stays open (half-close per RFC 9000).
        assert quic_stream._read_closed is False

    async def test_finish_write_is_idempotent(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Sending FIN twice would be a protocol error; idempotency prevents this."""
        await quic_stream.finish_write()
        await quic_stream.finish_write()
        mock_protocol._quic.send_stream_data.assert_called_once()


# ---------------------------------------------------------------------------
# QuicStream — full close (both directions)
# ---------------------------------------------------------------------------


class TestQuicStreamClose:
    """Tests for full stream close (both directions)."""

    async def test_close_sets_all_flags_and_sends_fin(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Closing marks both directions closed and sends FIN."""
        await quic_stream.close()
        assert quic_stream._closed is True
        assert quic_stream._write_closed is True
        assert quic_stream._read_closed is True
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"", end_stream=True)
        mock_protocol.transmit.assert_called_once()

    async def test_close_is_idempotent(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Second close is a no-op — prevents double-FIN."""
        await quic_stream.close()
        await quic_stream.close()
        mock_protocol._quic.send_stream_data.assert_called_once()


# ---------------------------------------------------------------------------
# QuicConnection — event handling per RFC 9000
#
# - StreamDataReceived: data from peer, may create new remote-initiated stream
# - StreamReset: abrupt stream termination by peer
# - ConnectionTerminated: all streams implicitly closed (RFC 9000 Section 10)
# ---------------------------------------------------------------------------


class TestQuicConnectionHandleEvent:
    """Tests for QUIC event dispatch on the connection."""

    def test_stream_data_creates_new_incoming_stream(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Per RFC 9000, receiving data on unknown stream ID creates a remote-initiated stream."""
        event = StreamDataReceived(data=b"hello", end_stream=False, stream_id=4)

        quic_connection._handle_event(event)

        assert 4 in quic_connection._streams
        assert quic_connection._incoming_streams.qsize() == 1
        incoming = quic_connection._incoming_streams.get_nowait()
        assert incoming.stream_id == 4
        assert incoming._read_buffer.get_nowait() == b"hello"

    def test_stream_data_delivers_to_existing_stream(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Data on existing stream is delivered without creating a new one."""
        existing = QuicStream(_protocol=mock_protocol, _stream_id=4)
        quic_connection._streams[4] = existing

        event = StreamDataReceived(data=b"more", end_stream=False, stream_id=4)
        quic_connection._handle_event(event)

        assert quic_connection._incoming_streams.qsize() == 0
        assert existing._read_buffer.get_nowait() == b"more"

    def test_stream_data_with_fin_delivers_data_and_signals_end(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """FIN bit delivers final data and signals graceful half-close."""
        event = StreamDataReceived(data=b"final", end_stream=True, stream_id=8)

        quic_connection._handle_event(event)

        stream = quic_connection._streams[8]
        assert stream._read_buffer.get_nowait() == b"final"
        # FIN sentinel
        assert stream._read_buffer.get_nowait() == b""

    def test_stream_reset_signals_error_not_eof(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Per RFC 9000 Section 3.2, RESET_STREAM is an error, not clean EOF.

        The stream must surface the error code to the application, and
        subsequent reads must raise rather than returning empty bytes.
        """
        existing = QuicStream(_protocol=mock_protocol, _stream_id=4)
        quic_connection._streams[4] = existing

        event = StreamReset(error_code=42, stream_id=4)
        quic_connection._handle_event(event)

        assert existing._reset_error is not None
        assert existing._reset_error.error_code == 42
        assert existing._reset_error.stream_id == 4

    def test_stream_reset_unknown_stream_ignored(self, quic_connection: QuicConnection) -> None:
        """Reset for unknown stream ID is silently ignored (may already be cleaned up)."""
        event = StreamReset(error_code=0, stream_id=999)
        # Must not raise.
        quic_connection._handle_event(event)

    def test_connection_terminated_resets_all_streams(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Per RFC 9000 Section 10, connection termination implicitly resets all streams.

        All open streams are assumed to have lost data. Reads must raise
        an error, not return empty bytes (which would imply clean EOF).
        """

        # Create two open streams on the connection.
        s1 = QuicStream(_protocol=mock_protocol, _stream_id=0)
        s2 = QuicStream(_protocol=mock_protocol, _stream_id=4)
        quic_connection._streams = {0: s1, 4: s2}

        # Simulate a CONNECTION_CLOSE from the peer.
        event = ConnectionTerminated(error_code=0, frame_type=None, reason_phrase="done")
        quic_connection._handle_event(event)

        # Connection is marked closed.
        assert quic_connection._closed is True

        # All streams received a reset, not a clean FIN.
        #
        # The reset error carries the connection-level error code.
        assert s1._reset_error is not None
        assert s1._reset_error.error_code == 0
        assert s2._reset_error is not None
        assert s2._reset_error.error_code == 0


# ---------------------------------------------------------------------------
# QuicConnection — open/accept/close
# ---------------------------------------------------------------------------


class TestQuicConnectionOpenStream:
    """Tests for opening new streams on a connection."""

    async def test_open_stream_when_closed_raises(self, quic_connection: QuicConnection) -> None:
        """Opening a stream on a closed connection raises an error."""
        quic_connection._closed = True
        with pytest.raises(QuicTransportError, match=r"Connection is closed"):
            await quic_connection.open_stream(ProtocolId("/test/1.0"))


class TestQuicConnectionAcceptStream:
    """Tests for accepting incoming streams."""

    async def test_accept_stream_when_closed_raises(self, quic_connection: QuicConnection) -> None:
        """Accepting a stream on a closed connection raises an error."""
        quic_connection._closed = True
        with pytest.raises(QuicTransportError, match=r"Connection is closed"):
            await quic_connection.accept_stream()

    async def test_accept_stream_returns_queued(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Accepting a stream returns one that was queued via event handling."""
        event = StreamDataReceived(data=b"init", end_stream=False, stream_id=12)
        quic_connection._handle_event(event)

        stream = await quic_connection.accept_stream()
        assert stream.stream_id == 12


class TestQuicConnectionClose:
    """Tests for closing a QUIC connection."""

    async def test_close_marks_closed_and_closes_streams(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Closing sends CONNECTION_CLOSE and closes all streams."""
        s1 = QuicStream(_protocol=mock_protocol, _stream_id=0)
        s2 = QuicStream(_protocol=mock_protocol, _stream_id=4)
        quic_connection._streams = {0: s1, 4: s2}

        await quic_connection.close()

        assert quic_connection._closed is True
        assert s1._closed is True
        assert s2._closed is True
        mock_protocol._quic.close.assert_called_once()
        mock_protocol.transmit.assert_called()

    async def test_close_is_idempotent(
        self, quic_connection: QuicConnection, mock_protocol: MagicMock
    ) -> None:
        """Second close is a no-op — prevents double CONNECTION_CLOSE."""
        await quic_connection.close()
        await quic_connection.close()
        mock_protocol._quic.close.assert_called_once()


# ---------------------------------------------------------------------------
# LibP2PQuicProtocol — handshake, event routing, buffering
#
# Per libp2p-QUIC spec, ALPN protocol is "libp2p".
# Events between handshake completion and connection assignment must be buffered.
# ---------------------------------------------------------------------------


class TestLibP2PQuicProtocol:
    """Tests for the custom QUIC protocol event handler."""

    @pytest.fixture
    def protocol(self) -> LibP2PQuicProtocol:
        """A protocol with mocked parent internals (bypasses aioquic constructor)."""
        proto = LibP2PQuicProtocol.__new__(LibP2PQuicProtocol)
        proto.connection = None
        proto.peer_identity = None
        proto.handshake_complete = asyncio.Event()
        proto._buffered_events = []
        proto._on_handshake = None
        proto._quic = MagicMock()
        proto._quic._streams = {}
        proto.transmit = MagicMock()
        return proto

    def test_handshake_completed_sets_event(self, protocol: LibP2PQuicProtocol) -> None:
        """Handshake completion is signaled so the connection wrapper can proceed."""
        event = HandshakeCompleted(
            alpn_protocol="libp2p", early_data_accepted=False, session_resumed=False
        )
        protocol.quic_event_received(event)
        assert protocol.handshake_complete.is_set()

    def test_server_handshake_invokes_callback(self, protocol: LibP2PQuicProtocol) -> None:
        """Server-side callback is invoked on first handshake (before connection is set)."""
        callback = MagicMock()
        protocol._on_handshake = callback

        event = HandshakeCompleted(
            alpn_protocol="libp2p", early_data_accepted=False, session_resumed=False
        )
        protocol.quic_event_received(event)
        callback.assert_called_once_with(protocol)

    def test_callback_skipped_when_connection_already_exists(
        self, protocol: LibP2PQuicProtocol, mock_protocol: MagicMock, peer_a: PeerId
    ) -> None:
        """Callback is NOT invoked if connection is already assigned (client-side reconnect)."""
        callback = MagicMock()
        protocol._on_handshake = callback
        protocol.connection = QuicConnection(
            _protocol=mock_protocol,
            _peer_id=peer_a,
            _remote_addr="/ip4/127.0.0.1/udp/9000/quic-v1",
        )

        event = HandshakeCompleted(
            alpn_protocol="libp2p", early_data_accepted=False, session_resumed=False
        )
        protocol.quic_event_received(event)
        callback.assert_not_called()

    def test_events_forwarded_to_connection(
        self, protocol: LibP2PQuicProtocol, mock_protocol: MagicMock, peer_a: PeerId
    ) -> None:
        """Events are forwarded to the connection when it is assigned."""
        conn = QuicConnection(
            _protocol=mock_protocol,
            _peer_id=peer_a,
            _remote_addr="/ip4/127.0.0.1/udp/9000/quic-v1",
        )
        protocol.connection = conn

        event = StreamDataReceived(data=b"hello", end_stream=False, stream_id=0)
        protocol.quic_event_received(event)

        assert 0 in conn._streams
        assert conn._streams[0]._read_buffer.get_nowait() == b"hello"

    def test_events_buffered_between_handshake_and_connection(
        self, protocol: LibP2PQuicProtocol
    ) -> None:
        """Events after handshake but before connection assignment are buffered.

        This addresses a real race: the peer may open streams immediately after
        TLS completes, before the application creates the connection wrapper.
        """
        handshake = HandshakeCompleted(
            alpn_protocol="libp2p", early_data_accepted=False, session_resumed=False
        )
        protocol.quic_event_received(handshake)

        stream_event = StreamDataReceived(data=b"buffered", end_stream=False, stream_id=0)
        protocol.quic_event_received(stream_event)

        # HandshakeCompleted itself falls through to the buffering path, plus stream event.
        assert len(protocol._buffered_events) == 2
        assert protocol._buffered_events[1] is stream_event

    def test_events_before_handshake_dropped(self, protocol: LibP2PQuicProtocol) -> None:
        """Events before handshake are dropped (no app data before TLS per QUIC)."""
        event = StreamDataReceived(data=b"early", end_stream=False, stream_id=0)
        protocol.quic_event_received(event)
        assert len(protocol._buffered_events) == 0

    def test_replay_forwards_and_clears_buffered_events(
        self, protocol: LibP2PQuicProtocol, mock_protocol: MagicMock, peer_a: PeerId
    ) -> None:
        """Replaying delivers buffered events to the connection and clears the buffer."""
        handshake = HandshakeCompleted(
            alpn_protocol="libp2p", early_data_accepted=False, session_resumed=False
        )
        protocol.quic_event_received(handshake)

        e1 = StreamDataReceived(data=b"first", end_stream=False, stream_id=0)
        protocol.quic_event_received(e1)
        e2 = StreamDataReceived(data=b"second", end_stream=False, stream_id=0)
        protocol.quic_event_received(e2)

        conn = QuicConnection(
            _protocol=mock_protocol,
            _peer_id=peer_a,
            _remote_addr="/ip4/127.0.0.1/udp/9000/quic-v1",
        )
        protocol.connection = conn
        protocol._replay_buffered_events()

        assert protocol._buffered_events == []
        assert 0 in conn._streams
        assert conn._streams[0]._read_buffer.qsize() == 2

    def test_replay_noop_without_connection(self, protocol: LibP2PQuicProtocol) -> None:
        """Replay is a no-op when connection is not yet assigned."""
        protocol._buffered_events = [MagicMock()]
        protocol._replay_buffered_events()
        assert len(protocol._buffered_events) == 1

    def test_replay_noop_when_empty(
        self, protocol: LibP2PQuicProtocol, mock_protocol: MagicMock, peer_a: PeerId
    ) -> None:
        """Replay is a no-op when there are no buffered events."""
        protocol.connection = QuicConnection(
            _protocol=mock_protocol,
            _peer_id=peer_a,
            _remote_addr="/ip4/127.0.0.1/udp/9000/quic-v1",
        )
        protocol._replay_buffered_events()
        assert protocol._buffered_events == []

    def test_handshake_exception_sets_peer_identity_none(
        self, protocol: LibP2PQuicProtocol
    ) -> None:
        """Handshake completes even if certificate extraction raises.

        The except branch is defensive — if the try block inside the
        handshake handler raises, the handshake must still complete
        so the connection can proceed.
        """
        # Trigger a standard handshake event.
        event = HandshakeCompleted(
            alpn_protocol="libp2p", early_data_accepted=False, session_resumed=False
        )

        # Force the first assignment to peer_identity to raise.
        #
        # This simulates a failure during certificate extraction.
        # The except branch catches it and sets peer_identity = None.
        original_setattr = object.__setattr__
        call_count = 0

        def raising_setattr(self_inner: object, name: str, value: object) -> None:
            nonlocal call_count
            if name == "peer_identity" and call_count == 0:
                call_count += 1
                raise RuntimeError("cert extraction failed")
            original_setattr(self_inner, name, value)

        with patch.object(type(protocol), "__setattr__", raising_setattr):
            protocol.quic_event_received(event)

        # Despite the exception, handshake completed and identity is set.
        assert protocol.peer_identity is None
        assert protocol.handshake_complete.is_set()


class TestQuicStreamProtocolId:
    """Tests for the protocol_id property on QuicStream.

    Each QUIC stream carries a negotiated protocol identifier set during
    multistream-select. The default is empty until negotiation completes.
    """

    def test_protocol_id_returns_set_value(self, mock_protocol: MagicMock) -> None:
        """After negotiation, protocol_id reflects the agreed protocol."""
        stream = QuicStream(
            _protocol=mock_protocol,
            _stream_id=0,
            _protocol_id=ProtocolId("/test/1.0"),
        )
        assert stream.protocol_id == ProtocolId("/test/1.0")

    def test_protocol_id_default_empty(self, quic_stream: QuicStream) -> None:
        """Before negotiation, protocol_id is an empty string."""
        assert quic_stream.protocol_id == ProtocolId("")


class TestQuicStreamWriteFinDetection:
    """Tests for write detecting aioquic's internal FIN state.

    aioquic tracks per-stream state internally. If FIN was already sent
    (e.g., due to a race between close and write), the write method must
    detect this and fail early with a clear error rather than letting
    aioquic raise an opaque exception.
    """

    async def test_write_detects_aioquic_fin_sent(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Write raises when aioquic has already sent FIN on this stream.

        This catches the race where close() sends FIN but write() is
        called before our _write_closed flag is set.
        """

        # Simulate aioquic's internal stream with FIN already sent.
        mock_internal_stream = MagicMock()
        mock_internal_stream.send_fin = True
        mock_protocol._quic._streams = {0: mock_internal_stream}

        with pytest.raises(QuicTransportError, match=r"aioquic FIN already sent"):
            await quic_stream.write(b"data")

        # Write side is permanently closed after detecting FIN.
        assert quic_stream._write_closed is True

    async def test_write_proceeds_when_no_fin(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Write succeeds normally when the internal stream has not sent FIN."""

        # Simulate aioquic's internal stream in normal state.
        mock_internal_stream = MagicMock()
        mock_internal_stream.send_fin = False
        mock_protocol._quic._streams = {0: mock_internal_stream}

        await quic_stream.write(b"data")
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"data")

    async def test_write_proceeds_when_stream_not_in_map(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Write succeeds when aioquic has no entry for this stream ID.

        This happens for newly created streams before any data is sent.
        """
        mock_protocol._quic._streams = {}

        await quic_stream.write(b"data")
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"data")


class TestQuicStreamWriteException:
    """Tests for write wrapping exceptions from aioquic.

    When aioquic raises during a write, the error is wrapped in
    QuicTransportError. If the error message indicates a terminal
    condition (FIN sent or stream closed), the write side is also
    marked closed to prevent further attempts.
    """

    async def test_write_wraps_fin_exception_and_marks_closed(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """An exception mentioning 'FIN' permanently closes the write side.

        This heuristic detects terminal errors from aioquic's internals.
        """

        # Simulate aioquic raising a FIN-related error.
        mock_protocol._quic.send_stream_data.side_effect = RuntimeError("FIN already sent")

        with pytest.raises(QuicTransportError, match=r"Write failed on stream 0"):
            await quic_stream.write(b"data")

        # Write side is permanently closed.
        assert quic_stream._write_closed is True

    async def test_write_wraps_closed_exception_and_marks_closed(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """An exception mentioning 'closed' permanently closes the write side."""

        # Simulate aioquic raising a stream-closed error.
        mock_protocol._quic.send_stream_data.side_effect = RuntimeError("stream is closed")

        with pytest.raises(QuicTransportError, match=r"Write failed on stream 0"):
            await quic_stream.write(b"data")

        assert quic_stream._write_closed is True

    async def test_write_wraps_unrelated_exception_without_marking_closed(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Transient errors keep the write side open for retry.

        Only terminal conditions (FIN, closed) should permanently close.
        A buffer overflow or similar transient error should not.
        """

        # Simulate a transient error unrelated to stream state.
        mock_protocol._quic.send_stream_data.side_effect = RuntimeError("buffer overflow")

        with pytest.raises(QuicTransportError, match=r"Write failed on stream 0"):
            await quic_stream.write(b"data")

        # Write side stays open — the error was transient.
        assert quic_stream._write_closed is False


class TestQuicConnectionProperties:
    """Tests for QuicConnection read-only property accessors.

    These properties expose the peer identity and address that were
    established during connection setup.
    """

    def test_peer_id_returns_set_value(
        self, quic_connection: QuicConnection, peer_a: PeerId
    ) -> None:
        """The connection exposes the peer ID set during construction."""
        assert quic_connection.peer_id == peer_a

    def test_remote_addr_returns_set_value(self, quic_connection: QuicConnection) -> None:
        """The connection exposes the remote multiaddr set during construction."""
        assert quic_connection.remote_addr == "/ip4/127.0.0.1/udp/9000/quic-v1"


class TestQuicConnectionOpenStreamHappyPath:
    """Tests for opening a stream with successful protocol negotiation.

    Opening a stream involves three steps:

    1. Allocate a QUIC stream ID from aioquic
    2. Run multistream-select to negotiate the application protocol
    3. Store the negotiated protocol ID on the stream
    """

    @patch(
        "lean_spec.subspecs.networking.transport.quic.connection.QuicStreamAdapter",
    )
    async def test_open_stream_creates_and_negotiates(
        self,
        mock_adapter_cls: MagicMock,
        quic_connection: QuicConnection,
        mock_protocol: MagicMock,
    ) -> None:
        """Full stream opening flow: allocate ID, negotiate, return stream.

        The adapter wraps the raw QUIC stream for multistream-select.
        After negotiation, the protocol ID is stored on the stream.
        """

        # aioquic assigns stream ID 8 for the new stream.
        mock_protocol._quic.get_next_available_stream_id.return_value = 8

        # Simulate successful protocol negotiation via the adapter.
        mock_adapter = MagicMock()
        mock_adapter.negotiate_lazy_client = AsyncMock(return_value=ProtocolId("/test/1.0"))
        mock_adapter_cls.return_value = mock_adapter

        stream = await quic_connection.open_stream(ProtocolId("/test/1.0"))

        # Verify the stream was created with the correct ID and protocol.
        assert stream.stream_id == 8
        assert stream.protocol_id == ProtocolId("/test/1.0")
        assert 8 in quic_connection._streams

        # Verify negotiation was attempted and data was flushed.
        mock_adapter.negotiate_lazy_client.assert_awaited_once_with(ProtocolId("/test/1.0"))
        mock_protocol.transmit.assert_called()


class TestLibP2PQuicProtocolInit:
    """Tests for LibP2PQuicProtocol construction.

    The parent class (aioquic's QuicConnectionProtocol) requires real
    QUIC internals. Patching the parent constructor lets us verify
    our custom attributes are initialized correctly in isolation.
    """

    def test_init_with_mocked_quic_config(self) -> None:
        """All custom attributes start in their expected initial state.

        Connection and peer identity are None until handshake completes.
        The handshake event is unset. No events are buffered yet.
        """

        # Bypass the parent constructor that needs real aioquic internals.
        with patch.object(LibP2PQuicProtocol.__bases__[0], "__init__", return_value=None):
            protocol = LibP2PQuicProtocol()

        assert protocol.connection is None
        assert protocol.peer_identity is None
        assert not protocol.handshake_complete.is_set()
        assert protocol._buffered_events == []


class TestQuicConnectionManagerCreate:
    """Tests for QuicConnectionManager.create factory method.

    Creation generates a libp2p-TLS certificate, writes it to temp files
    (aioquic requires file paths), and configures QUIC with the libp2p
    ALPN protocol and CERT_NONE (peer verification uses the libp2p
    certificate extension, not a CA chain).
    """

    @patch("lean_spec.subspecs.networking.transport.quic.connection.generate_libp2p_certificate")
    async def test_create_generates_cert_and_configures_quic(
        self, mock_gen_cert: MagicMock
    ) -> None:
        """Full creation flow: generate cert, write to disk, configure QUIC.

        The certificate is written to temp files because aioquic only
        accepts file paths for TLS configuration.
        """

        # Simulate certificate generation returning PEM + DER bytes.
        mock_gen_cert.return_value = (b"PRIVATE-KEY", b"CERTIFICATE", b"DER-CERT")

        # Simulate an identity keypair that produces a known peer ID.
        mock_identity = MagicMock()
        mock_peer_id = PeerId.from_base58("peerA")
        mock_identity.to_peer_id.return_value = mock_peer_id

        # Intercept QUIC configuration to avoid real TLS operations.
        with patch(
            "lean_spec.subspecs.networking.transport.quic.connection.QuicConfiguration"
        ) as mock_config_cls:
            mock_config = MagicMock()
            mock_config_cls.return_value = mock_config

            manager = await QuicConnectionManager.create(mock_identity)

        # Verify the manager was configured correctly.
        assert manager.peer_id == mock_peer_id
        mock_gen_cert.assert_called_once_with(mock_identity)
        mock_config_cls.assert_called_once_with(
            alpn_protocols=[LIBP2P_ALPN_PROTOCOL],
            is_client=True,
            verify_mode=ssl.CERT_NONE,
        )
        mock_config.load_cert_chain.assert_called_once()

        # Verify temp files were written with the certificate data.
        assert manager._temp_dir is not None
        assert (manager._temp_dir / "cert.pem").read_bytes() == b"CERTIFICATE"
        assert (manager._temp_dir / "key.pem").read_bytes() == b"PRIVATE-KEY"


class TestQuicConnectionManagerConnect:
    """Tests for outbound QUIC connection establishment.

    Connecting parses the multiaddr, creates a QUIC session via aioquic,
    waits for the TLS handshake, and wraps the result in a QuicConnection.
    If the multiaddr includes a p2p component, the expected peer ID is used
    directly. Otherwise a temporary peer ID is generated (full certificate
    verification is not yet implemented).
    """

    @pytest.fixture
    def manager(self) -> QuicConnectionManager:
        """A manager with mocked internals for outbound connection tests."""
        mock_identity = MagicMock()
        mock_peer_id = PeerId.from_base58("peerA")
        mock_config = MagicMock(spec=["load_cert_chain"])
        return QuicConnectionManager(
            _identity_key=mock_identity,
            _peer_id=mock_peer_id,
            _config=mock_config,
            _temp_dir=Path("/tmp/test"),
        )

    async def test_connect_non_quic_raises(self, manager: QuicConnectionManager) -> None:
        """Connecting to a non-QUIC multiaddr is rejected immediately."""
        with pytest.raises(QuicTransportError, match=r"Not a QUIC multiaddr"):
            await manager.connect("/ip4/127.0.0.1/udp/9000")

    @patch("lean_spec.subspecs.networking.transport.quic.connection.quic_connect")
    async def test_connect_happy_path_with_peer_id(
        self, mock_quic_connect: MagicMock, manager: QuicConnectionManager
    ) -> None:
        """When the multiaddr includes a p2p component, that peer ID is used.

        This is the normal case — the caller knows who they're connecting to.
        """

        # Simulate a protocol whose TLS handshake already completed.
        mock_protocol = MagicMock(spec=LibP2PQuicProtocol)
        mock_protocol.handshake_complete = asyncio.Event()
        mock_protocol.handshake_complete.set()
        mock_protocol.connection = None
        mock_protocol._buffered_events = []
        mock_protocol._replay_buffered_events = MagicMock()

        # Wire quic_connect to return our pre-configured protocol.
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_protocol)
        mock_quic_connect.return_value = mock_cm

        # Connect to a multiaddr that includes a peer ID.
        multiaddr = "/ip4/127.0.0.1/udp/9000/quic-v1/p2p/peerB"
        conn = await manager.connect(multiaddr)

        # The peer ID from the multiaddr is used, not a generated one.
        assert conn.peer_id == PeerId.from_base58("peerB")
        assert conn.remote_addr == multiaddr

        # Buffered events from the handshake window are replayed.
        mock_protocol._replay_buffered_events.assert_called_once()

    @patch("lean_spec.subspecs.networking.transport.quic.connection.IdentityKeypair")
    @patch("lean_spec.subspecs.networking.transport.quic.connection.quic_connect")
    async def test_connect_happy_path_without_peer_id(
        self,
        mock_quic_connect: MagicMock,
        mock_identity_cls: MagicMock,
        manager: QuicConnectionManager,
    ) -> None:
        """Without a p2p component, a temporary peer ID is generated.

        Full peer certificate verification is not yet implemented.
        This fallback allows connections to proceed during development.
        """

        # Simulate a protocol whose TLS handshake already completed.
        mock_protocol = MagicMock(spec=LibP2PQuicProtocol)
        mock_protocol.handshake_complete = asyncio.Event()
        mock_protocol.handshake_complete.set()
        mock_protocol.connection = None
        mock_protocol._buffered_events = []
        mock_protocol._replay_buffered_events = MagicMock()

        # Wire quic_connect to return our pre-configured protocol.
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_protocol)
        mock_quic_connect.return_value = mock_cm

        # Simulate generation of a temporary identity keypair.
        temp_peer = PeerId.from_base58("tempPeer")
        mock_temp_key = MagicMock()
        mock_temp_key.to_peer_id.return_value = temp_peer
        mock_identity_cls.generate.return_value = mock_temp_key

        # Connect without a peer ID in the multiaddr.
        conn = await manager.connect("/ip4/127.0.0.1/udp/9000/quic-v1")

        # A temporary peer ID was generated and used.
        assert conn.peer_id == temp_peer

    @patch("lean_spec.subspecs.networking.transport.quic.connection.quic_connect")
    async def test_connect_wraps_exception(
        self, mock_quic_connect: MagicMock, manager: QuicConnectionManager
    ) -> None:
        """Connection failures are wrapped in QuicTransportError.

        The original exception is preserved as the cause.
        """

        # Simulate a network-level failure during connection.
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(side_effect=OSError("connection refused"))
        mock_quic_connect.return_value = mock_cm

        with pytest.raises(QuicTransportError, match=r"Failed to connect"):
            await manager.connect("/ip4/127.0.0.1/udp/9000/quic-v1")


class TestQuicConnectionManagerListen:
    """Tests for inbound QUIC connection acceptance.

    The listener creates a server-side QUIC configuration, starts
    quic_serve, and installs a protocol factory. Each new connection
    triggers a handshake callback that creates a QuicConnection wrapper.
    """

    @pytest.fixture
    def manager_with_temp_dir(self, tmp_path: Path) -> QuicConnectionManager:
        """A manager with a real temp dir containing cert files.

        Uses tmp_path so cert files exist on disk for load_cert_chain.
        """
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        cert_path.write_bytes(b"CERTIFICATE")
        key_path.write_bytes(b"PRIVATE-KEY")

        mock_identity = MagicMock()
        mock_peer_id = PeerId.from_base58("peerA")
        mock_config = MagicMock()
        return QuicConnectionManager(
            _identity_key=mock_identity,
            _peer_id=mock_peer_id,
            _config=mock_config,
            _temp_dir=tmp_path,
        )

    async def test_listen_non_quic_raises(
        self, manager_with_temp_dir: QuicConnectionManager
    ) -> None:
        """Listening on a non-QUIC multiaddr is rejected immediately."""
        callback = AsyncMock()
        with pytest.raises(QuicTransportError, match=r"Not a QUIC multiaddr"):
            await manager_with_temp_dir.listen("/ip4/0.0.0.0/udp/9000", callback)

    @patch("lean_spec.subspecs.networking.transport.quic.connection.QuicConfiguration")
    @patch("lean_spec.subspecs.networking.transport.quic.connection.quic_serve")
    async def test_listen_configures_server_and_serves(
        self,
        mock_quic_serve: MagicMock,
        mock_config_cls: MagicMock,
        manager_with_temp_dir: QuicConnectionManager,
    ) -> None:
        """Server uses is_client=False, CERT_NONE, and the libp2p ALPN.

        CERT_NONE is correct because peer verification happens via
        the libp2p certificate extension, not a CA chain.
        """

        # Intercept server config creation.
        mock_server_config = MagicMock()
        mock_config_cls.return_value = mock_server_config
        mock_quic_serve.return_value = MagicMock()

        callback = AsyncMock()

        # Force the shutdown event to raise immediately so listen() exits.
        mock_event = MagicMock()
        mock_event.wait = AsyncMock(side_effect=asyncio.CancelledError)

        with (
            patch(
                "lean_spec.subspecs.networking.transport.quic.connection.asyncio.Event"
            ) as mock_event_cls,
            pytest.raises(asyncio.CancelledError),
        ):
            mock_event_cls.return_value = mock_event
            await manager_with_temp_dir.listen("/ip4/0.0.0.0/udp/9000/quic-v1", callback)

        # Verify the server was configured as a non-client with libp2p ALPN.
        mock_config_cls.assert_called_once_with(
            alpn_protocols=[LIBP2P_ALPN_PROTOCOL],
            is_client=False,
            verify_mode=ssl.CERT_NONE,
        )
        mock_server_config.load_cert_chain.assert_called_once()
        mock_quic_serve.assert_awaited_once()

    @patch("lean_spec.subspecs.networking.transport.quic.connection.QuicConfiguration")
    @patch("lean_spec.subspecs.networking.transport.quic.connection.quic_serve")
    @patch("lean_spec.subspecs.networking.transport.quic.connection.IdentityKeypair")
    async def test_listen_handle_handshake_creates_connection(
        self,
        mock_identity_cls: MagicMock,
        mock_quic_serve: MagicMock,
        mock_config_cls: MagicMock,
        manager_with_temp_dir: QuicConnectionManager,
    ) -> None:
        """The handshake callback creates and registers a QuicConnection.

        This test captures the protocol factory that listen() passes to
        quic_serve, then invokes the handshake callback to verify that
        a connection is correctly wired up and registered.
        """
        mock_config_cls.return_value = MagicMock()

        # Simulate generation of a remote peer identity.
        temp_peer = PeerId.from_base58("remotePeer")
        mock_temp_key = MagicMock()
        mock_temp_key.to_peer_id.return_value = temp_peer
        mock_identity_cls.generate.return_value = mock_temp_key

        # Capture the protocol factory that listen() passes to quic_serve.
        captured_create_protocol = None

        async def capture_serve(*args: object, **kwargs: object) -> MagicMock:
            nonlocal captured_create_protocol
            captured_create_protocol = kwargs.get("create_protocol")
            return MagicMock()

        mock_quic_serve.side_effect = capture_serve

        callback = AsyncMock()

        # Force the shutdown event to raise immediately so listen() exits.
        mock_event = MagicMock()
        mock_event.wait = AsyncMock(side_effect=asyncio.CancelledError)

        with (
            patch(
                "lean_spec.subspecs.networking.transport.quic.connection.asyncio.Event"
            ) as mock_event_cls,
            pytest.raises(asyncio.CancelledError),
        ):
            mock_event_cls.return_value = mock_event
            await manager_with_temp_dir.listen("/ip4/0.0.0.0/udp/9000/quic-v1", callback)

        # The factory must have been captured from quic_serve kwargs.
        assert captured_create_protocol is not None

        # Create a protocol instance using the captured factory.
        #
        # The parent constructor is patched to avoid aioquic dependencies.
        with patch.object(LibP2PQuicProtocol.__bases__[0], "__init__", return_value=None):
            proto_instance = captured_create_protocol()

        # The factory must have attached a handshake callback.
        assert proto_instance._on_handshake is not None

        # Simulate the handshake callback being invoked by aioquic.
        proto_instance._quic = MagicMock()
        proto_instance.transmit = MagicMock()
        proto_instance.connection = None
        proto_instance._buffered_events = []

        proto_instance._on_handshake(proto_instance)

        # The callback creates a connection and registers it in the manager.
        assert proto_instance.connection is not None
        assert proto_instance.connection.peer_id == temp_peer
        assert temp_peer in manager_with_temp_dir._connections

    @patch("lean_spec.subspecs.networking.transport.quic.connection.QuicConfiguration")
    @patch("lean_spec.subspecs.networking.transport.quic.connection.quic_serve")
    async def test_listen_without_temp_dir_skips_cert_loading(
        self,
        mock_quic_serve: MagicMock,
        mock_config_cls: MagicMock,
    ) -> None:
        """Without a temp directory, cert loading is skipped gracefully.

        This guards against a crash if the manager was not constructed
        via the normal create() factory.
        """

        # Intercept server config creation.
        mock_server_config = MagicMock()
        mock_config_cls.return_value = mock_server_config
        mock_quic_serve.return_value = MagicMock()

        # Create a manager with no temp directory (no cert files on disk).
        manager = QuicConnectionManager(
            _identity_key=MagicMock(),
            _peer_id=PeerId.from_base58("peerA"),
            _config=MagicMock(),
            _temp_dir=None,
        )
        callback = AsyncMock()

        # Force the shutdown event to raise immediately so listen() exits.
        mock_event = MagicMock()
        mock_event.wait = AsyncMock(side_effect=asyncio.CancelledError)

        with (
            patch(
                "lean_spec.subspecs.networking.transport.quic.connection.asyncio.Event"
            ) as mock_event_cls,
            pytest.raises(asyncio.CancelledError),
        ):
            mock_event_cls.return_value = mock_event
            await manager.listen("/ip4/0.0.0.0/udp/9000/quic-v1", callback)

        # Cert loading was skipped because no temp dir exists.
        mock_server_config.load_cert_chain.assert_not_called()
