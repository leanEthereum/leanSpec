"""Tests for connection manager."""

from __future__ import annotations

import asyncio

import pytest

from lean_spec.subspecs.networking.transport import PeerId
from lean_spec.subspecs.networking.transport.connection.manager import (
    NOISE_PROTOCOL_ID,
    SUPPORTED_MUXERS,
    ConnectionManager,
    TransportConnectionError,
    YamuxConnection,
    _parse_multiaddr,
)
from lean_spec.subspecs.networking.transport.identity import IdentityKeypair
from lean_spec.subspecs.networking.transport.noise.crypto import generate_keypair
from lean_spec.subspecs.networking.transport.yamux.frame import YAMUX_PROTOCOL_ID


class TestConstants:
    """Tests for connection manager constants."""

    def test_noise_protocol_id(self) -> None:
        """Noise protocol ID is /noise."""
        assert NOISE_PROTOCOL_ID == "/noise"

    def test_supported_muxers_includes_yamux(self) -> None:
        """Supported muxers includes yamux."""
        assert YAMUX_PROTOCOL_ID in SUPPORTED_MUXERS

    def test_supported_muxers_is_list(self) -> None:
        """Supported muxers is a list (ordered by preference)."""
        assert isinstance(SUPPORTED_MUXERS, list)


class TestParseMultiaddr:
    """Tests for _parse_multiaddr helper."""

    def test_parse_ip4_tcp(self) -> None:
        """Parse /ip4/.../tcp/... address."""
        host, port = _parse_multiaddr("/ip4/127.0.0.1/tcp/9000")
        assert host == "127.0.0.1"
        assert port == 9000

    def test_parse_ip4_tcp_different_values(self) -> None:
        """Parse different IP and port values."""
        host, port = _parse_multiaddr("/ip4/192.168.1.100/tcp/8080")
        assert host == "192.168.1.100"
        assert port == 8080

    def test_parse_with_peer_id(self) -> None:
        """Parse address with /p2p/... peer ID (ignored)."""
        host, port = _parse_multiaddr("/ip4/192.168.1.1/tcp/8080/p2p/QmPeerId123")
        assert host == "192.168.1.1"
        assert port == 8080

    def test_parse_with_leading_slash(self) -> None:
        """Parse address with leading slash."""
        host, port = _parse_multiaddr("/ip4/10.0.0.1/tcp/3000")
        assert host == "10.0.0.1"
        assert port == 3000

    def test_parse_without_leading_slash(self) -> None:
        """Parse address without leading slash."""
        host, port = _parse_multiaddr("ip4/10.0.0.1/tcp/3000")
        assert host == "10.0.0.1"
        assert port == 3000

    def test_parse_missing_host_raises(self) -> None:
        """Missing host raises ValueError."""
        with pytest.raises(ValueError, match="No host"):
            _parse_multiaddr("/tcp/9000")

    def test_parse_missing_port_raises(self) -> None:
        """Missing port raises ValueError."""
        with pytest.raises(ValueError, match="No port"):
            _parse_multiaddr("/ip4/127.0.0.1")

    def test_parse_empty_raises(self) -> None:
        """Empty address raises ValueError."""
        with pytest.raises(ValueError, match="No host"):
            _parse_multiaddr("")

    def test_parse_only_ip4_raises(self) -> None:
        """Only ip4 component raises ValueError for missing port."""
        with pytest.raises(ValueError, match="No port"):
            _parse_multiaddr("/ip4/127.0.0.1")

    def test_parse_only_tcp_raises(self) -> None:
        """Only tcp component raises ValueError for missing host."""
        with pytest.raises(ValueError, match="No host"):
            _parse_multiaddr("/tcp/9000")


class TestConnectionManagerCreate:
    """Tests for ConnectionManager.create()."""

    def test_create_generates_key(self) -> None:
        """Create without keys generates new keypairs."""
        manager = ConnectionManager.create()

        # Identity key (secp256k1) for PeerId
        assert manager._identity_key is not None
        assert len(manager._identity_key.public_key_bytes()) == 33

        # Noise key (X25519) for encryption
        assert manager._noise_private is not None
        assert len(manager._noise_public.public_bytes_raw()) == 32

    def test_create_with_existing_key(self) -> None:
        """Create with keys uses provided keys."""
        identity_key = IdentityKeypair.generate()
        noise_key, noise_public = generate_keypair()
        manager = ConnectionManager.create(identity_key=identity_key, noise_key=noise_key)

        # Compare the raw bytes of the keys
        assert manager._noise_public.public_bytes_raw() == noise_public.public_bytes_raw()
        assert manager._identity_key.public_key_bytes() == identity_key.public_key_bytes()

    def test_create_derives_peer_id(self) -> None:
        """Create derives PeerId from identity key."""
        manager = ConnectionManager.create()

        # PeerId is now a dataclass with a multihash field
        assert len(manager.peer_id.multihash) > 0
        # secp256k1 PeerIds start with "16Uiu2" when Base58 encoded
        assert str(manager.peer_id).startswith("16Uiu2")

    def test_create_starts_with_empty_connections(self) -> None:
        """Create starts with no active connections."""
        manager = ConnectionManager.create()

        assert len(manager._connections) == 0

    def test_create_peer_id_deterministic(self) -> None:
        """Same identity key produces same PeerId."""
        identity_key = IdentityKeypair.generate()

        # Different noise keys, same identity key
        manager1 = ConnectionManager.create(identity_key=identity_key)
        manager2 = ConnectionManager.create(identity_key=identity_key)

        assert manager1.peer_id == manager2.peer_id

    def test_create_different_keys_different_peer_ids(self) -> None:
        """Different identity keys produce different PeerIds."""
        manager1 = ConnectionManager.create()
        manager2 = ConnectionManager.create()

        assert manager1.peer_id != manager2.peer_id


class TestConnectionManagerProperties:
    """Tests for ConnectionManager properties."""

    def test_peer_id_property(self) -> None:
        """peer_id property returns local PeerId."""
        manager = ConnectionManager.create()

        peer_id = manager.peer_id

        assert isinstance(peer_id, PeerId)
        assert len(peer_id.multihash) > 10  # PeerIds have reasonably long multihash


class TestYamuxConnectionProperties:
    """Tests for YamuxConnection properties."""

    def test_peer_id_property(self) -> None:
        """peer_id property returns remote peer ID."""
        test_peer_id = PeerId.from_base58("QmTestPeer123")
        conn = _create_mock_connection(peer_id=test_peer_id)

        assert conn.peer_id == test_peer_id

    def test_remote_addr_property(self) -> None:
        """remote_addr property returns address."""
        conn = _create_mock_connection(remote_addr="/ip4/127.0.0.1/tcp/9000")

        assert conn.remote_addr == "/ip4/127.0.0.1/tcp/9000"


class TestYamuxConnectionClose:
    """Tests for YamuxConnection.close()."""

    def test_close_sets_closed_flag(self) -> None:
        """Close sets the _closed flag."""

        async def run_test() -> bool:
            conn = _create_mock_connection()

            await conn.close()
            return conn._closed

        assert asyncio.run(run_test()) is True

    def test_close_is_idempotent(self) -> None:
        """Closing twice is safe."""

        async def run_test() -> None:
            conn = _create_mock_connection()

            await conn.close()
            await conn.close()  # Should not raise

        asyncio.run(run_test())

    def test_close_cancels_read_task(self) -> None:
        """Close cancels the background read task."""

        async def run_test() -> bool:
            conn = _create_mock_connection()

            # Create a dummy task
            async def dummy_task() -> None:
                await asyncio.sleep(10)

            conn._read_task = asyncio.create_task(dummy_task())

            await conn.close()
            return conn._read_task.cancelled()

        assert asyncio.run(run_test()) is True


class TestYamuxConnectionOpenStream:
    """Tests for YamuxConnection.open_stream()."""

    def test_open_stream_on_closed_connection_raises(self) -> None:
        """Opening stream on closed connection raises error."""

        async def run_test() -> None:
            conn = _create_mock_connection()
            conn._closed = True

            with pytest.raises(TransportConnectionError, match="closed"):
                await conn.open_stream("/test/protocol")

        asyncio.run(run_test())


class TestTransportConnectionError:
    """Tests for TransportConnectionError."""

    def test_error_is_exception(self) -> None:
        """TransportConnectionError is an Exception."""
        error = TransportConnectionError("test")
        assert isinstance(error, Exception)

    def test_error_message(self) -> None:
        """Error contains message."""
        error = TransportConnectionError("connection failed")
        assert "connection failed" in str(error)


# Helper functions


def _create_mock_connection(
    peer_id: PeerId | None = None,
    remote_addr: str = "/ip4/127.0.0.1/tcp/9000",
) -> YamuxConnection:
    """Create a mock YamuxConnection for testing."""
    if peer_id is None:
        peer_id = PeerId.from_base58("QmTestPeer")
    return YamuxConnection(
        _yamux=MockYamuxSession(),  # type: ignore[arg-type]
        _peer_id=peer_id,
        _remote_addr=remote_addr,
    )


class MockYamuxSession:
    """Mock YamuxSession for testing."""

    def __init__(self) -> None:
        self._closed = False
        self._next_stream_id = 1  # Client uses odd IDs in yamux

    async def open_stream(self) -> "MockYamuxStream":
        stream_id = self._next_stream_id
        self._next_stream_id += 2
        return MockYamuxStream(stream_id=stream_id)

    async def close(self) -> None:
        self._closed = True


class MockYamuxStream:
    """Mock YamuxStream for testing."""

    def __init__(self, stream_id: int = 1) -> None:
        self.stream_id = stream_id
        self._protocol_id = ""

    async def read(self) -> bytes:
        return b""

    async def write(self, data: bytes) -> None:
        pass

    async def close(self) -> None:
        pass
