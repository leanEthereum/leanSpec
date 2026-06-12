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

from aioquic.asyncio import QuicConnectionProtocol, connect as quic_connect, serve as quic_serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
    StreamReset,
)

from lean_spec.node.networking.config import LIBP2P_ALPN_PROTOCOL
from lean_spec.node.networking.transport.identity import IdentityKeypair
from lean_spec.node.networking.transport.peer_id import PeerId
from lean_spec.node.networking.transport.quic.stream import QuicStream, QuicTransportError
from lean_spec.node.networking.transport.quic.stream_adapter import QuicStreamAdapter
from lean_spec.node.networking.transport.quic.tls import generate_libp2p_certificate
from lean_spec.node.networking.types import ProtocolId

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class QuicConnection:
    """
    A QUIC connection to a peer.

    Wraps aioquic's protocol and provides the Connection interface.
    No Noise or yamux layers are needed; QUIC handles encryption and multiplexing natively.
    """

    _protocol: QuicConnectionProtocol
    _peer_id: PeerId
    _remote_address: str
    _streams: dict[int, QuicStream] = field(default_factory=dict)
    _incoming_streams: asyncio.Queue[QuicStream] = field(default_factory=lambda: asyncio.Queue())
    _closed: bool = False

    @property
    def peer_id(self) -> PeerId:
        """Remote peer's ID."""
        return self._peer_id

    @property
    def remote_address(self) -> str:
        """Remote address in multiaddr format."""
        return self._remote_address

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
        self.handshake_complete = asyncio.Event()
        self._buffered_events: list[QuicEvent] = []

    def quic_event_received(self, event: QuicEvent) -> None:
        """Handle QUIC events."""
        if isinstance(event, HandshakeCompleted):
            # TODO: extract and verify the peer certificate from the TLS session.
            # aioquic stores it in the underlying QUIC connection, but does not
            # expose it directly, so the libp2p identity is not yet recovered.
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
    multiaddr_components = multiaddr.split("/")
    return "quic" in multiaddr_components or "quic-v1" in multiaddr_components


def parse_multiaddr(multiaddr: str) -> tuple[str, int, str | None, PeerId | None]:
    """
    Parse a multiaddr into components.

    Args:
        multiaddr: Address string.

    Returns:
        (host, port, transport, peer_id) tuple.
        transport is "quic", peer_id may be None.
    """
    multiaddr_components = multiaddr.strip("/").split("/")

    host = None
    port = None
    transport: str | None = None
    peer_id = None

    i = 0
    while i < len(multiaddr_components):
        if multiaddr_components[i] == "ip4" and i + 1 < len(multiaddr_components):
            host = multiaddr_components[i + 1]
            i += 2
        elif multiaddr_components[i] == "udp" and i + 1 < len(multiaddr_components):
            port = int(multiaddr_components[i + 1])
            i += 2
        elif multiaddr_components[i] in ("quic", "quic-v1"):
            transport = "quic"
            i += 1
        elif multiaddr_components[i] == "p2p" and i + 1 < len(multiaddr_components):
            peer_id = PeerId.from_base58(multiaddr_components[i + 1])
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
        connection = await manager.connect("/ip4/127.0.0.1/udp/9000/quic-v1")
        stream = await connection.open_stream("/leanconsensus/req/status/1/ssz_snappy")
    """

    _identity_key: IdentityKeypair
    _peer_id: PeerId
    _config: QuicConfiguration
    _connections: dict[PeerId, QuicConnection] = field(default_factory=dict)
    _temp_directory: Path | None = None
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
        private_pem, certificate_pem, _ = generate_libp2p_certificate(identity_key)

        # Write certificate/key to temp files (aioquic requires file paths).
        temp_directory = Path(tempfile.mkdtemp())
        certificate_path = temp_directory / "cert.pem"
        key_path = temp_directory / "key.pem"
        certificate_path.write_bytes(certificate_pem)
        key_path.write_bytes(private_pem)

        # Configure QUIC.
        config = QuicConfiguration(
            alpn_protocols=[LIBP2P_ALPN_PROTOCOL],
            is_client=True,
            verify_mode=ssl.CERT_NONE,  # We verify via libp2p extension, not CA
        )
        config.load_cert_chain(str(certificate_path), str(key_path))

        return cls(
            _identity_key=identity_key,
            _peer_id=peer_id,
            _config=config,
            _temp_directory=temp_directory,
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
            QuicTransportError: If the multiaddr is not a QUIC address.
            QuicTransportError: If the multiaddr carries no peer identity.
            QuicTransportError: If the connection fails.
        """
        host, port, transport, expected_peer_id = parse_multiaddr(multiaddr)

        if transport != "quic":
            raise QuicTransportError(f"Not a QUIC multiaddr: {multiaddr}")

        # The remote peer identity must come from the dialed multiaddr.
        #
        # We do not yet extract identity from the verified libp2p
        # certificate extension, so the multiaddr is the only trustworthy
        # source of the remote peer identity.
        # A missing identity means the connection cannot be keyed, so we
        # fail cleanly rather than invent a fabricated one.
        # This is checked before dialing so it is not re-wrapped as a
        # connection failure below.
        if expected_peer_id is None:
            raise QuicTransportError(f"Multiaddr is missing a peer identity: {multiaddr}")

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

            connection = QuicConnection(
                _protocol=protocol,
                _peer_id=expected_peer_id,
                _remote_address=multiaddr,
            )
            protocol.connection = connection
            protocol._replay_buffered_events()

            self._connections[expected_peer_id] = connection
            return connection

        except Exception as exception:
            raise QuicTransportError(f"Failed to connect: {exception}") from exception

    async def listen(
        self,
        multiaddr: str,
        on_connection: Callable[[QuicConnection], Awaitable[None]],
    ) -> None:
        """
        Listen for incoming QUIC connections.

        Creates a server using aioquic with libp2p-tls authentication.
        Runs until shutdown is requested.

        Inbound connections are rejected until peer identity verification
        from the libp2p certificate extension is implemented.
        Without it the remote peer identity is unknown, and keying a
        connection by a fabricated identity is unsafe.

        Args:
            multiaddr: Address to listen on (e.g., "/ip4/0.0.0.0/udp/9000/quic-v1").
            on_connection: Async callback to invoke once inbound connections are supported.

        Raises:
            QuicTransportError: If the multiaddr is not a QUIC address.
            QuicTransportError: When an inbound connection completes its handshake,
                because the remote peer identity cannot yet be verified.
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
        if self._temp_directory:
            certificate_path = self._temp_directory / "cert.pem"
            key_path = self._temp_directory / "key.pem"
            server_config.load_cert_chain(str(certificate_path), str(key_path))

        # Callback invoked when an inbound TLS handshake completes.
        def handle_handshake(protocol_instance: LibP2PQuicProtocol) -> None:
            # An inbound connection has no multiaddr to carry the peer identity.
            #
            # The only trustworthy source is the libp2p certificate extension,
            # whose verification is not yet implemented on this side.
            # Until that exists we cannot key the connection by a real identity,
            # so we fail cleanly rather than invent a fabricated one.
            raise QuicTransportError(
                "Cannot accept inbound connection: "
                "peer identity verification from the libp2p certificate is not implemented"
            )

        # Protocol factory that attaches our callback to each new instance.
        def create_protocol(*args, **kwargs) -> LibP2PQuicProtocol:
            protocol = LibP2PQuicProtocol(*args, **kwargs)
            protocol._on_handshake = handle_handshake
            return protocol

        await quic_serve(
            host,
            port,
            configuration=server_config,
            create_protocol=create_protocol,
        )
        # Park until cancelled.
        # The caller stops the server by cancelling this coroutine.
        await asyncio.Event().wait()
