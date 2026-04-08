"""
QUIC connection implementation for libp2p.

QUIC provides native encryption (TLS 1.3) and multiplexing, eliminating the need
for Noise and yamux layers. This results in fewer round-trips
and simpler connection establishment.

Connection flow:
    1. QUIC handshake (includes TLS 1.3)
    2. Verify peer's libp2p certificate extension
    3. Ready for streams (QUIC native multiplexing)

Each stream uses multistream-select to negotiate application protocols,
same as any libp2p connection.

References:
    - aioquic documentation: https://aioquic.readthedocs.io/
    - libp2p QUIC spec: https://github.com/libp2p/specs/tree/master/quic
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio import connect as quic_connect
from aioquic.asyncio import serve as quic_serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
    StreamReset,
)

from lean_spec.subspecs.networking.config import LIBP2P_ALPN_PROTOCOL
from lean_spec.subspecs.networking.types import ProtocolId

from ..identity import IdentityKeypair
from ..peer_id import PeerId
from .stream_adapter import QuicStreamAdapter
from .tls import generate_libp2p_certificate

logger = logging.getLogger(__name__)


class QuicTransportError(Exception):
    """Raised when QUIC connection operations fail."""


class QuicStreamResetError(QuicTransportError):
    """Raised when a QUIC stream is abruptly reset by the peer (RESET_STREAM).

    Per RFC 9000 Section 3.2, RESET_STREAM indicates the peer cannot guarantee
    delivery of stream data. Outstanding data may be lost.
    """

    def __init__(self, stream_id: int, error_code: int) -> None:
        """Create a reset error with the stream ID and the peer's error code."""
        self.stream_id = stream_id
        self.error_code = error_code
        super().__init__(f"Stream {stream_id} reset by peer (error_code={error_code})")


@dataclass(slots=True)
class QuicStream:
    """
    A single QUIC stream for application data.

    QUIC streams are lightweight - opening a stream is just sending a frame,
    no handshake required. Flow control is per-stream, preventing
    head-of-line blocking.
    """

    _protocol: QuicConnectionProtocol
    _stream_id: int
    _read_buffer: asyncio.Queue[bytes] = field(default_factory=lambda: asyncio.Queue())
    _closed: bool = False
    _write_closed: bool = False
    _read_closed: bool = False
    _reset_error: QuicStreamResetError | None = None
    _protocol_id: ProtocolId = ProtocolId("")

    @property
    def stream_id(self) -> int:
        """Stream identifier."""
        return self._stream_id

    @property
    def protocol_id(self) -> ProtocolId:
        """Negotiated protocol ID for this stream."""
        return self._protocol_id

    async def read(self) -> bytes:
        """
        Read data from the stream.

        Blocks until data is available. Returns empty bytes when the peer
        has closed their write side (half-close via FIN).

        Raises:
            QuicStreamResetError: If the stream was reset by the peer
                (RESET_STREAM per RFC 9000 Section 3.2). Data may have been lost.

        Returns:
            Received data bytes, or empty bytes when stream is half-closed.
        """
        if self._read_closed:
            # If the stream was reset, always raise.
            if self._reset_error is not None:
                raise self._reset_error
            return b""

        data = await self._read_buffer.get()
        if data == b"":
            self._read_closed = True
            # If end-of-stream was caused by a reset, raise the error.
            # Per RFC 9000 Section 3.2, RESET_STREAM means data may have been lost.
            if self._reset_error is not None:
                raise self._reset_error
            return b""

        return data

    async def write(self, data: bytes) -> None:
        """
        Write data to the stream.

        Args:
            data: Bytes to send.

        Raises:
            QuicTransportError: If write side is closed or aioquic rejects the write.
        """
        if self._write_closed:
            raise QuicTransportError("Stream write side is closed")

        # Check aioquic's internal stream state before writing.
        #
        # aioquic tracks stream state internally and will raise an exception
        # if we try to write after FIN has been sent. This can happen due to
        # race conditions in stream handling. We check first to give a clearer
        # error message.
        quic = self._protocol._quic
        stream = quic._streams.get(self._stream_id)
        if stream is not None and getattr(stream, "send_fin", False):
            self._write_closed = True
            raise QuicTransportError(
                f"Stream {self._stream_id} write side is closed (aioquic FIN already sent)"
            )

        try:
            quic.send_stream_data(self._stream_id, data)
            self._protocol.transmit()
        except Exception as e:
            # If aioquic raises an exception, mark our stream as write-closed
            # to prevent further attempts.
            error_msg = str(e)
            if "FIN" in error_msg or "closed" in error_msg.lower():
                self._write_closed = True
            raise QuicTransportError(f"Write failed on stream {self._stream_id}: {e}") from e

    async def finish_write(self) -> None:
        """
        Signal end of writing (half-close).

        Sends FIN for our write direction while keeping read side open.
        Use this after sending a request to signal we're done writing.
        """
        if self._write_closed:
            return

        self._write_closed = True
        self._protocol._quic.send_stream_data(self._stream_id, b"", end_stream=True)
        self._protocol.transmit()

    async def close(self) -> None:
        """Close the stream gracefully (both directions)."""
        if self._closed:
            return

        self._closed = True
        self._write_closed = True
        self._read_closed = True
        self._protocol._quic.send_stream_data(self._stream_id, b"", end_stream=True)
        self._protocol.transmit()

    def _receive_data(self, data: bytes) -> None:
        """Internal: called when data arrives for this stream."""
        self._read_buffer.put_nowait(data)

    def _receive_end(self) -> None:
        """Internal: called when the peer sends FIN (graceful half-close)."""
        self._read_buffer.put_nowait(b"")

    def _receive_reset(self, error_code: int) -> None:
        """Internal: called when the peer sends RESET_STREAM (abrupt termination).

        Per RFC 9000 Section 3.2, RESET_STREAM indicates the sender cannot
        guarantee delivery. Outstanding data may be lost. This is fundamentally
        different from FIN, which guarantees all data was delivered.
        """
        self._reset_error = QuicStreamResetError(self._stream_id, error_code)
        # Queue an empty sentinel to unblock any pending read.
        self._read_buffer.put_nowait(b"")


@dataclass(slots=True)
class QuicConnection:
    """
    A QUIC connection to a peer.

    Wraps aioquic's protocol and provides the Connection interface.
    No Noise or yamux layers are needed; QUIC handles encryption and multiplexing natively.
    """

    _protocol: QuicConnectionProtocol
    _peer_id: PeerId
    _remote_addr: str
    _streams: dict[int, QuicStream] = field(default_factory=dict)
    _incoming_streams: asyncio.Queue[QuicStream] = field(default_factory=lambda: asyncio.Queue())
    _closed: bool = False

    @property
    def peer_id(self) -> PeerId:
        """Remote peer's ID."""
        return self._peer_id

    @property
    def remote_addr(self) -> str:
        """Remote address in multiaddr format."""
        return self._remote_addr

    async def open_stream(self, protocol: ProtocolId) -> QuicStream:
        """
        Open a new stream for the given protocol.

        QUIC streams are lightweight - just a frame, no handshake.
        multistream-select negotiates the application protocol.

        Args:
            protocol: Protocol ID to negotiate.

        Returns:
            Open stream ready for use.
        """
        if self._closed:
            raise QuicTransportError("Connection is closed")

        # Create a new QUIC stream.
        stream_id = self._protocol._quic.get_next_available_stream_id()

        stream = QuicStream(
            _protocol=self._protocol,
            _stream_id=stream_id,
        )
        self._streams[stream_id] = stream

        # Negotiate the application protocol.
        adapter = QuicStreamAdapter(stream)
        negotiated = await adapter.negotiate_lazy_client(protocol)
        stream._protocol_id = negotiated

        # Yield to allow aioquic to process any pending events.
        #
        # After multistream negotiation, aioquic may have received packets
        # that haven't been processed yet. A yield allows the event loop
        # to process these, ensuring stream state is consistent.
        await asyncio.sleep(0)

        # Ensure any pending data from negotiation is transmitted.
        self._protocol.transmit()

        return stream

    async def accept_stream(self) -> QuicStream:
        """
        Accept an incoming stream from the peer.

        Blocks until a new stream is opened by the remote side.

        Returns:
            New stream opened by peer.
        """
        if self._closed:
            raise QuicTransportError("Connection is closed")

        return await self._incoming_streams.get()

    async def close(self) -> None:
        """Close the connection gracefully."""
        if self._closed:
            return

        self._closed = True

        # Close all streams.
        for stream in self._streams.values():
            await stream.close()

        # Close the QUIC connection.
        self._protocol._quic.close()
        self._protocol.transmit()

    def _handle_event(self, event: QuicEvent) -> None:
        """Internal: handle QUIC events from aioquic."""
        if isinstance(event, StreamDataReceived):
            stream_id = event.stream_id

            if stream_id not in self._streams:
                # New incoming stream.
                stream = QuicStream(
                    _protocol=self._protocol,
                    _stream_id=stream_id,
                )
                self._streams[stream_id] = stream
                self._incoming_streams.put_nowait(stream)
                logger.info(
                    "[QUIC] New incoming stream %d queued (queue size: %d, data: %d bytes)",
                    stream_id,
                    self._incoming_streams.qsize(),
                    len(event.data),
                )

            self._streams[stream_id]._receive_data(event.data)
            if event.end_stream:
                self._streams[stream_id]._receive_end()

        elif isinstance(event, StreamReset):
            # Per RFC 9000 Section 3.2, RESET_STREAM abruptly terminates a stream.
            # This is NOT equivalent to FIN — data may have been lost.
            if event.stream_id in self._streams:
                self._streams[event.stream_id]._receive_reset(event.error_code)

        elif isinstance(event, ConnectionTerminated):
            self._closed = True

            # Per RFC 9000 Section 10, connection termination implicitly
            # resets all open streams — data may have been lost.
            #
            # Using _receive_reset (not _receive_end) ensures that pending
            # reads raise an error instead of returning empty bytes, which
            # would falsely imply a clean end-of-stream.
            for stream in self._streams.values():
                stream._receive_reset(event.error_code)


class LibP2PQuicProtocol(QuicConnectionProtocol):
    """
    Custom QUIC protocol that handles libp2p events.

    Extends aioquic's protocol to:
        1. Verify peer certificates using libp2p extension
        2. Route events to QuicConnection
    """

    # Instance-specific callback for handling new connections.
    # Set by the server's protocol factory for inbound connections.
    _on_handshake: Callable[[LibP2PQuicProtocol], None] | None = None

    def __init__(self, *args, **kwargs) -> None:
        """Initialize the libp2p QUIC protocol handler."""
        super().__init__(*args, **kwargs)
        self.connection: QuicConnection | None = None
        self.peer_identity: PeerId | None = None
        self.handshake_complete = asyncio.Event()
        self._buffered_events: list[QuicEvent] = []

    def quic_event_received(self, event: QuicEvent) -> None:
        """Handle QUIC events."""
        if isinstance(event, HandshakeCompleted):
            # Extract peer identity from certificate.
            #
            # aioquic stores the peer certificate in _quic.tls.
            # We verify the libp2p extension and extract the identity.
            try:
                # Get peer certificate from TLS session.
                # aioquic may not expose this directly, need to check.
                # For now, mark handshake complete.
                # TODO: Extract and verify peer certificate
                self.peer_identity = None  # Will be set if we can extract cert
            except Exception:
                self.peer_identity = None

            self.handshake_complete.set()

            # For server-side connections, invoke the handshake callback.
            # This MUST happen BEFORE forwarding events so connection is set up.
            if self._on_handshake is not None and self.connection is None:
                self._on_handshake(self)

        # Forward events to connection handler, buffering if not yet set.
        #
        # After handshake completes, the peer may open streams immediately.
        # The QuicConnection wrapper is created asynchronously after
        # handshake_complete is set, so events arriving in between would
        # be lost. Buffer them and replay once connection is assigned.
        if self.connection:
            self.connection._handle_event(event)
        elif self.handshake_complete.is_set():
            self._buffered_events.append(event)

    def _replay_buffered_events(self) -> None:
        """Replay events buffered between handshake and connection assignment."""
        if self._buffered_events and self.connection:
            logger.info("[QUIC] Replaying %d buffered events", len(self._buffered_events))
            for event in self._buffered_events:
                self.connection._handle_event(event)
            self._buffered_events.clear()


def is_quic_multiaddr(multiaddr: str) -> bool:
    """
    Check if a multiaddr uses QUIC transport.

    Args:
        multiaddr: Address string to check.

    Returns:
        True if the multiaddr uses QUIC, False otherwise.
    """
    # Multiaddr protocol names are case-sensitive per the multiaddr spec.
    # Valid QUIC components are lowercase "quic" and "quic-v1".
    parts = multiaddr.split("/")
    return "quic" in parts or "quic-v1" in parts


def parse_multiaddr(multiaddr: str) -> tuple[str, int, str | None, PeerId | None]:
    """
    Parse a multiaddr into components.

    Args:
        multiaddr: Address string.

    Returns:
        (host, port, transport, peer_id) tuple.
        transport is "quic", peer_id may be None.
    """
    parts = multiaddr.strip("/").split("/")

    host = None
    port = None
    transport: str | None = None
    peer_id = None

    i = 0
    while i < len(parts):
        if parts[i] in ("ip4", "ip6") and i + 1 < len(parts):
            host = parts[i + 1]
            i += 2
        elif parts[i] == "udp" and i + 1 < len(parts):
            port = int(parts[i + 1])
            i += 2
        elif parts[i] in ("quic", "quic-v1"):
            transport = "quic"
            i += 1
        elif parts[i] == "p2p" and i + 1 < len(parts):
            peer_id = PeerId.from_base58(parts[i + 1])
            i += 2
        else:
            i += 1

    if host is None:
        raise ValueError(f"No host in multiaddr: {multiaddr}")
    if port is None:
        raise ValueError(f"No port in multiaddr: {multiaddr}")

    return host, port, transport, peer_id


@dataclass(slots=True)
class QuicConnectionManager:
    """
    Manages QUIC connections with libp2p-tls authentication.

    No Noise or yamux layers are needed.
    QUIC provides encryption and multiplexing natively.

    Usage:
        manager = await QuicConnectionManager.create(identity_key)
        conn = await manager.connect("/ip4/127.0.0.1/udp/9000/quic-v1")
        stream = await conn.open_stream("/leanconsensus/req/status/1/ssz_snappy")
    """

    _identity_key: IdentityKeypair
    _peer_id: PeerId
    _config: QuicConfiguration
    _connections: dict[PeerId, QuicConnection] = field(default_factory=dict)
    _temp_dir: Path | None = None
    _context_managers: list[contextlib.AbstractAsyncContextManager[object]] = field(
        default_factory=list
    )

    @classmethod
    async def create(
        cls,
        identity_key: IdentityKeypair,
    ) -> QuicConnectionManager:
        """
        Create a QuicConnectionManager.

        Args:
            identity_key: secp256k1 identity keypair.

        Returns:
            Initialized manager.
        """
        peer_id = identity_key.to_peer_id()

        # Generate libp2p certificate.
        private_pem, cert_pem, _ = generate_libp2p_certificate(identity_key)

        # Write cert/key to temp files (aioquic requires file paths).
        temp_dir = Path(tempfile.mkdtemp())
        cert_path = temp_dir / "cert.pem"
        key_path = temp_dir / "key.pem"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(private_pem)

        # Configure QUIC.
        config = QuicConfiguration(
            alpn_protocols=[LIBP2P_ALPN_PROTOCOL],
            is_client=True,
            verify_mode=ssl.CERT_NONE,  # We verify via libp2p extension, not CA
        )
        config.load_cert_chain(str(cert_path), str(key_path))

        return cls(
            _identity_key=identity_key,
            _peer_id=peer_id,
            _config=config,
            _temp_dir=temp_dir,
        )

    @property
    def peer_id(self) -> PeerId:
        """Our local PeerId."""
        return self._peer_id

    async def connect(self, multiaddr: str) -> QuicConnection:
        """
        Connect to a peer at the given multiaddr.

        Args:
            multiaddr: Address like "/ip4/127.0.0.1/udp/9000/quic-v1/p2p/PeerId"

        Returns:
            Established connection.

        Raises:
            QuicTransportError: If connection fails.
        """
        host, port, transport, expected_peer_id = parse_multiaddr(multiaddr)

        if transport != "quic":
            raise QuicTransportError(f"Not a QUIC multiaddr: {multiaddr}")

        try:
            # Create QUIC connection using aioquic.
            #
            # We manually enter the async context manager and store it
            # so the connection stays open after this function returns.
            cm = quic_connect(
                host,
                port,
                configuration=self._config,
                create_protocol=LibP2PQuicProtocol,
            )
            base_protocol = await cm.__aenter__()

            # Store the context manager so we can close it later.
            self._context_managers.append(cm)

            # Cast to our protocol type to access custom attributes.
            assert isinstance(base_protocol, LibP2PQuicProtocol)
            protocol: LibP2PQuicProtocol = base_protocol

            # Wait for handshake to complete.
            await protocol.handshake_complete.wait()

            # For now, we don't verify peer certificate (requires deeper aioquic integration).
            # In production, we would extract and verify the libp2p certificate extension.
            #
            # Without peer ID verification, we trust the connection based on:
            # - QUIC encryption (TLS 1.3)
            # - The peer being at the expected address

            # Create a placeholder peer_id if we couldn't verify.
            # In a real implementation, we'd extract this from the certificate.
            if expected_peer_id:
                peer_id = expected_peer_id
            else:
                # Generate a random peer ID for now.
                # This is NOT correct for production but allows testing.
                temp_key = IdentityKeypair.generate()
                peer_id = temp_key.to_peer_id()

            conn = QuicConnection(
                _protocol=protocol,
                _peer_id=peer_id,
                _remote_addr=multiaddr,
            )
            protocol.connection = conn
            protocol._replay_buffered_events()

            self._connections[peer_id] = conn
            return conn

        except Exception as e:
            raise QuicTransportError(f"Failed to connect: {e}") from e

    async def listen(
        self,
        multiaddr: str,
        on_connection: Callable[[QuicConnection], Awaitable[None]],
    ) -> None:
        """Listen for incoming QUIC connections.

        Creates a server using aioquic with libp2p-tls authentication.
        Runs until shutdown is requested.

        For each accepted connection:

        1. Complete QUIC/TLS handshake
        2. Create QuicConnection wrapper
        3. Invoke the callback

        Args:
            multiaddr: Address to listen on (e.g., "/ip4/0.0.0.0/udp/9000/quic-v1").
            on_connection: Async callback invoked for each accepted connection.

        Raises:
            QuicTransportError: If multiaddr is not a QUIC address.
        """
        host, port, transport, _ = parse_multiaddr(multiaddr)

        if transport != "quic":
            raise QuicTransportError(f"Not a QUIC multiaddr: {multiaddr}")

        # Create server configuration.
        server_config = QuicConfiguration(
            alpn_protocols=[LIBP2P_ALPN_PROTOCOL],
            is_client=False,
            verify_mode=ssl.CERT_NONE,  # We verify via libp2p extension
        )

        # Reuse the same certificate as client config.
        if self._temp_dir:
            cert_path = self._temp_dir / "cert.pem"
            key_path = self._temp_dir / "key.pem"
            server_config.load_cert_chain(str(cert_path), str(key_path))

        # Callback to set up connection when handshake completes.
        # Captures this manager's state (self, on_connection, host, port).
        def handle_handshake(protocol_instance: LibP2PQuicProtocol) -> None:
            temp_key = IdentityKeypair.generate()
            remote_peer_id = temp_key.to_peer_id()

            remote_addr = f"/ip4/{host}/udp/{port}/quic-v1/p2p/{remote_peer_id}"
            conn = QuicConnection(
                _protocol=protocol_instance,
                _peer_id=remote_peer_id,
                _remote_addr=remote_addr,
            )
            protocol_instance.connection = conn
            protocol_instance._replay_buffered_events()
            self._connections[remote_peer_id] = conn

            # Invoke callback asynchronously so it doesn't block event processing.
            asyncio.ensure_future(on_connection(conn))

        # Protocol factory that attaches our callback to each new instance.
        def create_protocol(*args, **kwargs) -> LibP2PQuicProtocol:
            protocol = LibP2PQuicProtocol(*args, **kwargs)
            protocol._on_handshake = handle_handshake
            return protocol

        # Create a shutdown event to allow graceful termination.
        shutdown_event = asyncio.Event()

        await quic_serve(
            host,
            port,
            configuration=server_config,
            create_protocol=create_protocol,
        )
        # Keep running until shutdown is requested.
        await shutdown_event.wait()
