"""
Connection manager: TCP -> Noise -> yamux stack.

The ConnectionManager handles the full connection lifecycle:
    1. TCP connect or accept
    2. multistream-select to negotiate /noise
    3. Noise XX handshake (mutual authentication)
    4. multistream-select to negotiate /yamux/1.0.0
    5. yamux session ready for application streams

Both outbound (connect) and inbound (accept) connections follow
the same flow, just with different initiator/responder roles.

Architecture Overview
---------------------

libp2p builds secure, multiplexed connections through protocol layering.
Each layer adds a capability:

    TCP          -> Reliable byte stream (no security, no multiplexing)
    Noise        -> Encryption + authentication (still single stream)
    yamux        -> Multiple logical streams over one connection with flow control

The key insight: we negotiate TWICE with multistream-select.

First negotiation (plaintext):
    Both peers agree to use Noise for encryption. This happens over raw TCP
    because we have no secure channel yet. An attacker could see that we're
    using Noise, but that's public information anyway.

Second negotiation (encrypted):
    Both peers agree to use yamux for multiplexing. This happens inside the
    Noise channel because the multiplexer choice might leak information about
    client software. More importantly, it proves the encryption works.

Why yamux over mplex? mplex is deprecated in libp2p due to lack of flow control.
yamux provides per-stream flow control (256KB window), preventing fast senders
from overwhelming slow receivers and avoiding head-of-line blocking.

Why this order? Security requires that TCP comes first (we need a transport),
encryption comes before multiplexing (protect all traffic), and each protocol
must be negotiated before use (both peers must agree).

References:
    - libp2p connection establishment: https://docs.libp2p.io/concepts/
    - multistream-select: https://github.com/multiformats/multistream-select
    - Noise framework: https://noiseprotocol.org/noise.html
    - yamux spec: https://github.com/hashicorp/yamux/blob/master/spec.md
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Protocol

from cryptography.hazmat.primitives.asymmetric import x25519

from ..identity import IdentityKeypair
from ..multistream import negotiate_client, negotiate_lazy_client, negotiate_server
from ..noise.crypto import generate_keypair
from ..noise.session import (
    NoiseSession,
    perform_handshake_initiator,
    perform_handshake_responder,
)
from ..peer_id import PeerId
from ..yamux.frame import YAMUX_PROTOCOL_ID
from ..yamux.session import YamuxSession, YamuxStream
from .types import Stream


class YamuxStreamProtocol(Protocol):
    """Protocol for YamuxStream interface used by connection manager."""

    stream_id: int
    """Stream identifier."""

    async def read(self) -> bytes:
        """Read data from the stream."""
        ...

    async def write(self, data: bytes) -> None:
        """Write data to the stream."""
        ...

    async def close(self) -> None:
        """Close the stream."""
        ...


class YamuxSessionProtocol(Protocol):
    """Protocol for YamuxSession interface used by connection manager."""

    async def open_stream(self) -> YamuxStreamProtocol:
        """Open a new stream."""
        ...

    async def close(self) -> None:
        """Close the session."""
        ...


NOISE_PROTOCOL_ID = "/noise"
"""Noise protocol ID for multistream negotiation."""

SUPPORTED_MUXERS = [YAMUX_PROTOCOL_ID]
"""Supported multiplexer protocols in preference order."""


class TransportConnectionError(Exception):
    """Raised when connection operations fail."""


@dataclass(slots=True)
class YamuxConnection:
    """
    A secure, multiplexed connection to a peer.

    Wraps a yamux session and provides the Connection interface.

    This class represents a fully established connection: TCP connected,
    Noise authenticated, and yamux ready. From the application's perspective,
    it's just a pipe to a peer that can carry multiple concurrent streams.

    yamux provides flow control (256KB per stream) which prevents head-of-line
    blocking that plagued the deprecated mplex multiplexer.
    """

    _yamux: YamuxSession
    """Underlying yamux session."""

    _peer_id: PeerId
    """Remote peer's ID (derived from their verified secp256k1 identity key)."""

    _remote_addr: str
    """Remote address in multiaddr format."""

    _read_task: asyncio.Task[None] | None = None
    """
    Background task running the yamux read loop.

    Why store this reference? Without it, the task becomes orphaned. Python's
    garbage collector may cancel orphaned tasks, breaking the connection. By
    keeping a reference, we ensure:

        1. The task stays alive as long as the connection exists
        2. We can cancel it cleanly during close()
        3. We can await it to ensure proper shutdown

    This pattern prevents the common asyncio bug where background tasks silently
    disappear because nothing holds a reference to them.
    """

    _closed: bool = False
    """Whether the connection has been closed."""

    @property
    def peer_id(self) -> PeerId:
        """Remote peer's ID."""
        return self._peer_id

    @property
    def remote_addr(self) -> str:
        """Remote address in multiaddr format."""
        return self._remote_addr

    async def open_stream(self, protocol: str) -> Stream:
        """
        Open a new stream for the given protocol.

        Performs multistream-select negotiation on the new stream.

        Args:
            protocol: Protocol ID to negotiate

        Returns:
            Open stream ready for use
        """
        if self._closed:
            raise TransportConnectionError("Connection is closed")

        # Create a new yamux stream.
        #
        # This allocates a stream ID and sends SYN to the remote peer. The stream
        # is now open for bidirectional communication, but we haven't agreed
        # on what protocol to speak yet.
        yamux_stream = await self._yamux.open_stream()

        # Negotiate the application protocol.
        #
        # This is the THIRD multistream-select negotiation (after Noise and yamux).
        # Each stream can speak a different protocol, so we negotiate per-stream.
        #
        # We use "lazy" negotiation here: send our protocol choice without waiting
        # for multistream header confirmation. This saves a round-trip when the
        # server supports our protocol (common case). If the server rejects, we'll
        # find out when we try to read.
        stream_wrapper = _StreamNegotiationWrapper(yamux_stream)
        negotiated = await negotiate_lazy_client(
            stream_wrapper.reader,
            stream_wrapper.writer,
            protocol,
        )

        # Record which protocol we're speaking on this stream.
        #
        # This metadata helps with debugging and protocol routing.
        yamux_stream._protocol_id = negotiated

        return yamux_stream

    async def accept_stream(self) -> Stream:
        """
        Accept an incoming stream from the peer.

        Blocks until a new stream is opened by the remote side.

        Returns:
            New stream opened by peer.

        Raises:
            TransportConnectionError: If connection is closed.
        """
        if self._closed:
            raise TransportConnectionError("Connection is closed")

        return await self._yamux.accept_stream()

    async def close(self) -> None:
        """Close the connection gracefully."""
        if self._closed:
            return

        self._closed = True

        # Cancel the background read task.
        #
        # The read loop runs forever until cancelled. We must stop it before
        # closing the yamux session, otherwise it might try to read from a
        # closed transport and raise confusing errors.
        #
        # The await ensures the task has fully stopped before we proceed.
        # CancelledError is expected and swallowed - it's not an error here.
        if self._read_task is not None and not self._read_task.done():
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                pass

        await self._yamux.close()


@dataclass(slots=True)
class ConnectionManager:
    """
    Manages the TCP -> Noise -> yamux connection stack.

    Two separate keypairs are used (matching ream/zeam and libp2p standard):
        - Identity key (secp256k1): Used to derive PeerId and sign identity proofs
        - Noise key (X25519): Used for Noise XX handshake encryption

    Usage:
        manager = ConnectionManager.create()
        conn = await manager.connect("/ip4/127.0.0.1/tcp/9000")
        stream = await conn.open_stream("/leanconsensus/req/status/1/ssz_snappy")
    """

    _identity_key: IdentityKeypair
    """
    Our secp256k1 identity key for PeerId derivation.

    This key establishes our network identity:
        1. PeerId is derived from the compressed public key (33 bytes)
        2. During Noise handshake, we sign the Noise static key to prove ownership

    Using secp256k1 matches ream, zeam, and the broader Ethereum libp2p network.
    """

    _noise_private: x25519.X25519PrivateKey
    """
    Our X25519 static key for Noise encryption.

    This key is used in the Noise XX handshake to establish session encryption keys.
    It is separate from the identity key because:
        1. Noise requires X25519, not secp256k1
        2. Separation allows identity key rotation without breaking encryption
        3. This is the standard libp2p approach (identity binding via signature)
    """

    _noise_public: x25519.X25519PublicKey
    """Our X25519 public key for Noise."""

    _peer_id: PeerId
    """Our PeerId (derived from identity key)."""

    _connections: dict[PeerId, YamuxConnection] = field(default_factory=dict)
    """Active connections by peer ID."""

    _server: asyncio.Server | None = None
    """TCP server if listening."""

    @classmethod
    def create(
        cls,
        identity_key: IdentityKeypair | None = None,
        noise_key: x25519.X25519PrivateKey | None = None,
    ) -> ConnectionManager:
        """
        Create a ConnectionManager with optional existing keys.

        Args:
            identity_key: secp256k1 keypair for identity. If None, generates new.
            noise_key: X25519 private key for Noise. If None, generates new.

        Returns:
            Initialized ConnectionManager
        """
        if identity_key is None:
            identity_key = IdentityKeypair.generate()

        if noise_key is None:
            noise_key, noise_public = generate_keypair()
        else:
            noise_public = noise_key.public_key()

        # Derive PeerId from our secp256k1 identity key.
        #
        # In libp2p, identity IS cryptographic. Your PeerId is derived from your
        # identity public key, making it verifiable. During Noise handshake, we
        # exchange identity proofs (signature over Noise static key) to prove
        # we own the claimed identity.
        peer_id = identity_key.to_peer_id()

        return cls(
            _identity_key=identity_key,
            _noise_private=noise_key,
            _noise_public=noise_public,
            _peer_id=peer_id,
        )

    @property
    def peer_id(self) -> PeerId:
        """Our local PeerId."""
        return self._peer_id

    @property
    def identity_key(self) -> IdentityKeypair:
        """Our identity keypair for peer ID derivation."""
        return self._identity_key

    async def connect(self, multiaddr: str) -> YamuxConnection:
        """
        Connect to a peer at the given multiaddr.

        Args:
            multiaddr: Address like "/ip4/127.0.0.1/tcp/9000"

        Returns:
            Established connection

        Raises:
            TransportConnectionError: If connection fails
        """
        # Parse the multiaddr to extract transport parameters.
        #
        # Multiaddrs are self-describing addresses. "/ip4/127.0.0.1/tcp/9000"
        # means: IPv4 address 127.0.0.1, TCP port 9000. The format is extensible
        # (e.g., "/dns4/example.com/tcp/9000/p2p/QmPeerId").
        host, port = _parse_multiaddr(multiaddr)

        # Establish the TCP connection.
        #
        # This is layer 1 of our stack. TCP gives us a reliable, ordered byte
        # stream. It handles packet loss, reordering, and retransmission. But it
        # provides no encryption, authentication, or multiplexing.
        reader, writer = await asyncio.open_connection(host, port)

        try:
            return await self._establish_outbound(reader, writer, multiaddr)
        except Exception as e:
            writer.close()
            await writer.wait_closed()
            raise TransportConnectionError(f"Failed to connect: {e}") from e

    async def listen(
        self,
        multiaddr: str,
        on_connection: Callable[[YamuxConnection], Awaitable[None]],
    ) -> None:
        """
        Listen for incoming connections.

        Args:
            multiaddr: Address to listen on (e.g., "/ip4/0.0.0.0/tcp/9000")
            on_connection: Callback for each new connection
        """
        host, port = _parse_multiaddr(multiaddr)

        async def handle_client(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            try:
                # Build multiaddr from socket info.
                #
                # We need this to tell the application where the connection came from.
                peername = writer.get_extra_info("peername")
                remote_addr = f"/ip4/{peername[0]}/tcp/{peername[1]}"

                conn = await self._establish_inbound(reader, writer, remote_addr)
                await on_connection(conn)
            except Exception:
                writer.close()
                await writer.wait_closed()

        self._server = await asyncio.start_server(handle_client, host, port)
        await self._server.serve_forever()

    async def _establish_outbound(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        remote_addr: str,
    ) -> YamuxConnection:
        """
        Establish outbound connection (we are initiator).

        Sequence:
            1. multistream-select /noise
            2. Noise handshake (initiator)
            3. multistream-select /yamux/1.0.0
            4. Return ready connection

        The initiator role affects two things:
            - In multistream-select: we propose protocols
            - In Noise XX: we send the first handshake message
        """
        # =====================================================================
        # Step 1: Negotiate encryption protocol (plaintext negotiation)
        # =====================================================================
        #
        # This negotiation happens over raw TCP. Both peers must agree on an
        # encryption protocol before we can secure the channel. We propose /noise
        # and wait for the server to confirm.
        #
        # Why negotiate? The server might support multiple encryption protocols.
        # By negotiating, we ensure both peers use the same one. This also allows
        # protocol evolution without breaking backward compatibility.
        await negotiate_client(reader, writer, [NOISE_PROTOCOL_ID])

        # =====================================================================
        # Step 2: Noise XX handshake (mutual authentication)
        # =====================================================================
        #
        # The Noise XX pattern provides mutual authentication: both peers prove
        # they possess the private key for their claimed identity. After this
        # completes, we have:
        #
        #   1. Encryption keys for bidirectional communication
        #   2. The remote peer's static public key (their identity)
        #   3. Proof that the remote peer is who they claim to be
        #
        # XX means: initiator sends ephemeral, responder sends ephemeral+static,
        # initiator sends static. Both static keys are encrypted and authenticated.
        #
        # Identity binding: During handshake, we exchange secp256k1 identity keys
        # and signatures proving we own both identity key and Noise key.
        noise_session = await perform_handshake_initiator(
            reader, writer, self._noise_private, self._identity_key
        )

        # =====================================================================
        # Step 3: Negotiate multiplexer protocol (encrypted negotiation)
        # =====================================================================
        #
        # This is the SECOND multistream-select negotiation. It happens over the
        # encrypted Noise channel, not raw TCP. Why negotiate again?
        #
        #   1. Privacy: The multiplexer choice is now encrypted
        #   2. Verification: Proves the encryption actually works
        #   3. Flexibility: Could negotiate yamux instead of mplex
        #
        # We need a wrapper because NoiseSession has a different I/O interface
        # than asyncio streams. The wrapper adapts NoiseSession to look like
        # StreamReader/StreamWriter so multistream code works unchanged.
        noise_wrapper = _NoiseNegotiationWrapper(noise_session)
        muxer = await negotiate_client(
            noise_wrapper.reader,
            noise_wrapper.writer,
            SUPPORTED_MUXERS,
        )

        if muxer != YAMUX_PROTOCOL_ID:
            raise TransportConnectionError(f"Unsupported multiplexer: {muxer}")

        # =====================================================================
        # Step 4: Create the yamux session
        # =====================================================================
        #
        # Now we have encryption (Noise) and multiplexing (yamux). The yamux
        # session wraps the Noise session, reading encrypted frames and
        # demultiplexing them to the appropriate stream.
        yamux = YamuxSession(noise=noise_session, is_initiator=True)

        # Derive the remote peer's identity from their verified secp256k1 key.
        #
        # The remote identity was exchanged and verified during Noise handshake.
        # The signature proves they own both the identity key and the Noise key.
        peer_id = PeerId.from_secp256k1(noise_session.remote_identity)

        # Start the yamux read loop in the background.
        #
        # yamux is message-oriented: it reads frames from the Noise session and
        # routes them to stream-specific queues. This must run continuously to
        # handle incoming data, so we spawn a background task.
        #
        # CRITICAL: We store the task reference to prevent orphaning. See the
        # _read_task field documentation for details.
        read_task = asyncio.create_task(yamux.run())

        conn = YamuxConnection(
            _yamux=yamux,
            _peer_id=peer_id,
            _remote_addr=remote_addr,
            _read_task=read_task,
        )
        self._connections[peer_id] = conn

        return conn

    async def _establish_inbound(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        remote_addr: str,
    ) -> YamuxConnection:
        """
        Establish inbound connection (we are responder).

        Sequence:
            1. multistream-select /noise (server side)
            2. Noise handshake (responder)
            3. multistream-select /yamux/1.0.0 (server side)
            4. Return ready connection

        The responder role mirrors the initiator:
            - In multistream-select: we wait for proposals and confirm
            - In Noise XX: we wait for the first message, then respond
        """
        # =====================================================================
        # Step 1: Negotiate encryption protocol (server side)
        # =====================================================================
        #
        # As responder, we wait for the client to propose a protocol. We check
        # if we support it (we only support /noise) and confirm. The server
        # role is passive: wait, validate, respond.
        await negotiate_server(reader, writer, {NOISE_PROTOCOL_ID})

        # =====================================================================
        # Step 2: Noise XX handshake as responder
        # =====================================================================
        #
        # Same handshake as initiator, just different message order. We wait for
        # the initiator's first message, then respond. At the end, we have the
        # same result: encryption keys and verified peer identity.
        #
        # Identity binding: We exchange secp256k1 identity keys and signatures.
        noise_session = await perform_handshake_responder(
            reader, writer, self._noise_private, self._identity_key
        )

        # =====================================================================
        # Step 3: Negotiate multiplexer (server side, encrypted)
        # =====================================================================
        #
        # Same as initiator side, but we're the server. We wait for the client
        # to propose a multiplexer and confirm if we support it.
        noise_wrapper = _NoiseNegotiationWrapper(noise_session)
        muxer = await negotiate_server(
            noise_wrapper.reader,
            noise_wrapper.writer,
            set(SUPPORTED_MUXERS),
        )

        if muxer != YAMUX_PROTOCOL_ID:
            raise TransportConnectionError(f"Unsupported multiplexer: {muxer}")

        # =====================================================================
        # Step 4: Create yamux session (same as initiator)
        # =====================================================================
        yamux = YamuxSession(noise=noise_session, is_initiator=False)

        # Derive the remote peer's identity from their verified secp256k1 key.
        peer_id = PeerId.from_secp256k1(noise_session.remote_identity)

        # Start background read loop and store task reference.
        read_task = asyncio.create_task(yamux.run())

        conn = YamuxConnection(
            _yamux=yamux,
            _peer_id=peer_id,
            _remote_addr=remote_addr,
            _read_task=read_task,
        )
        self._connections[peer_id] = conn

        return conn


def _parse_multiaddr(multiaddr: str) -> tuple[str, int]:
    """
    Parse a multiaddr into host and port.

    Simple parser that handles /ip4/HOST/tcp/PORT format.

    Args:
        multiaddr: Address string

    Returns:
        (host, port) tuple

    Raises:
        ValueError: If multiaddr is malformed
    """
    # Split on "/" and process protocol/value pairs.
    #
    # Multiaddrs are a sequence of protocol/value pairs. "/ip4/127.0.0.1/tcp/9000"
    # becomes ["ip4", "127.0.0.1", "tcp", "9000"]. We iterate through pairs,
    # extracting the host and port values.
    parts = multiaddr.strip("/").split("/")

    host = None
    port = None

    i = 0
    while i < len(parts):
        if parts[i] == "ip4" and i + 1 < len(parts):
            host = parts[i + 1]
            i += 2
        elif parts[i] == "tcp" and i + 1 < len(parts):
            port = int(parts[i + 1])
            i += 2
        elif parts[i] == "p2p" and i + 1 < len(parts):
            # Skip peer ID component.
            #
            # Some multiaddrs include "/p2p/QmPeerId" to specify the expected
            # peer. We parse it out but don't verify (that happens in Noise).
            i += 2
        else:
            i += 1

    if host is None:
        raise ValueError(f"No host in multiaddr: {multiaddr}")
    if port is None:
        raise ValueError(f"No port in multiaddr: {multiaddr}")

    return host, port


# =============================================================================
# I/O Adapter Classes
# =============================================================================
#
# The classes below solve an interface mismatch problem. multistream-select
# expects asyncio.StreamReader/StreamWriter (the standard asyncio I/O interface).
# But after the Noise handshake, we communicate through NoiseSession, which has
# its own read/write methods.
#
# Rather than rewrite multistream to support multiple I/O interfaces, we create
# thin wrappers that make NoiseSession and YamuxStream look like asyncio streams.
# This is the Adapter pattern: same interface, different implementation.
#
# Why not just use asyncio streams everywhere? Because Noise and yamux add
# framing and encryption. A raw TCP read() might return part of a Noise frame,
# which is meaningless until you have the complete encrypted message. The
# session classes handle this framing internally.


class _NoiseNegotiationWrapper:
    """
    Wrapper to use NoiseSession with multistream negotiation.

    multistream-select expects asyncio.StreamReader/StreamWriter,
    but after Noise handshake we use NoiseSession for encrypted I/O.
    This wrapper bridges the two interfaces.

    The wrapper maintains a read buffer because NoiseSession.read() returns
    complete decrypted messages, but multistream might only want a few bytes.
    We buffer the excess for the next read.
    """

    __slots__ = ("_noise", "_buffer", "reader", "writer")

    def __init__(self, noise: NoiseSession) -> None:
        self._noise = noise
        self._buffer = b""

        # Create adapter objects that implement the StreamReader/StreamWriter
        # interface by delegating to this wrapper (and ultimately to NoiseSession).
        self.reader = _NoiseReader(self)
        self.writer = _NoiseWriter(self)


class _NoiseReader:
    """
    Fake StreamReader that reads from NoiseSession.

    Implements just enough of StreamReader's interface for multistream to work:
    read(n) and readexactly(n). Other methods (readline, etc.) are not needed.
    """

    __slots__ = ("_wrapper",)

    def __init__(self, wrapper: _NoiseNegotiationWrapper) -> None:
        self._wrapper = wrapper

    async def read(self, n: int) -> bytes:
        """Read up to n bytes."""
        # If buffer is empty, read a complete Noise message.
        #
        # NoiseSession.read() always returns a complete decrypted message.
        # This is different from TCP where read() might return partial data.
        if not self._wrapper._buffer:
            self._wrapper._buffer = await self._wrapper._noise.read()

        # Return up to n bytes, keeping the rest buffered.
        result = self._wrapper._buffer[:n]
        self._wrapper._buffer = self._wrapper._buffer[n:]
        return result

    async def readexactly(self, n: int) -> bytes:
        """Read exactly n bytes."""
        # May need multiple Noise messages to get n bytes.
        #
        # Keep reading until we have enough. This handles the case where the
        # requested size spans multiple encrypted messages.
        result = b""
        while len(result) < n:
            chunk = await self.read(n - len(result))
            if not chunk:
                raise asyncio.IncompleteReadError(result, n)
            result += chunk
        return result


class _NoiseWriter:
    """
    Fake StreamWriter that writes to NoiseSession.

    Implements write() + drain() pattern. Data is buffered until drain() is
    called, then sent as a single encrypted Noise message. This matches how
    asyncio StreamWriter works: write() buffers, drain() flushes.
    """

    __slots__ = ("_wrapper", "_pending")

    def __init__(self, wrapper: _NoiseNegotiationWrapper) -> None:
        self._wrapper = wrapper
        self._pending = b""

    def write(self, data: bytes) -> None:
        """Buffer data for writing."""
        # Just accumulate data. We'll encrypt and send it all in drain().
        self._pending += data

    async def drain(self) -> None:
        """Flush pending data."""
        # Encrypt and send all buffered data as one Noise message.
        #
        # This is efficient: one encryption operation, one network send.
        # Callers should batch their writes and call drain() once.
        if self._pending:
            await self._wrapper._noise.write(self._pending)
            self._pending = b""

    def close(self) -> None:
        """No-op. Actual noise session is closed separately."""

    async def wait_closed(self) -> None:
        """No-op. Actual noise session is closed separately."""


class _StreamNegotiationWrapper:
    """
    Wrapper to use YamuxStream with multistream negotiation.

    Similar to _NoiseNegotiationWrapper but for yamux streams.

    When we open a new yamux stream, we need to negotiate the application
    protocol using multistream-select. But YamuxStream has its own read/write
    interface. This wrapper makes it look like a StreamReader/StreamWriter.
    """

    __slots__ = ("_stream", "_buffer", "reader", "writer")

    def __init__(self, stream: YamuxStream) -> None:
        self._stream = stream
        self._buffer = b""

        self.reader = _StreamReader(self)
        self.writer = _StreamWriter(self)


class _StreamReader:
    """
    Fake StreamReader that reads from YamuxStream.

    Same pattern as _NoiseReader: buffer complete messages, return partial.
    """

    __slots__ = ("_wrapper",)

    def __init__(self, wrapper: _StreamNegotiationWrapper) -> None:
        self._wrapper = wrapper

    async def read(self, n: int) -> bytes:
        """Read up to n bytes."""
        # YamuxStream.read() returns complete frames, so we buffer like NoiseReader.
        if not self._wrapper._buffer:
            self._wrapper._buffer = await self._wrapper._stream.read()

        result = self._wrapper._buffer[:n]
        self._wrapper._buffer = self._wrapper._buffer[n:]
        return result

    async def readexactly(self, n: int) -> bytes:
        """Read exactly n bytes."""
        result = b""
        while len(result) < n:
            chunk = await self.read(n - len(result))
            if not chunk:
                raise asyncio.IncompleteReadError(result, n)
            result += chunk
        return result


class _StreamWriter:
    """
    Fake StreamWriter that writes to YamuxStream.

    Same pattern as _NoiseWriter: buffer until drain().
    """

    __slots__ = ("_wrapper", "_pending")

    def __init__(self, wrapper: _StreamNegotiationWrapper) -> None:
        self._wrapper = wrapper
        self._pending = b""

    def write(self, data: bytes) -> None:
        """Buffer data for writing."""
        self._pending += data

    async def drain(self) -> None:
        """Flush pending data."""
        if self._pending:
            await self._wrapper._stream.write(self._pending)
            self._pending = b""

    def close(self) -> None:
        """No-op. Actual yamux stream is closed separately."""

    async def wait_closed(self) -> None:
        """No-op. Actual yamux stream is closed separately."""
