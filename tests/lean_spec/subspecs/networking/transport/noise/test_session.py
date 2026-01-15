"""Tests for Noise session (post-handshake encrypted communication)."""

from __future__ import annotations

import asyncio
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from lean_spec.subspecs.networking.transport.noise.constants import CipherKey
from lean_spec.subspecs.networking.transport.noise.session import (
    AUTH_TAG_SIZE,
    MAX_MESSAGE_SIZE,
    MAX_PLAINTEXT_SIZE,
    NoiseSession,
    SessionError,
    _recv_handshake_message,
    _send_handshake_message,
)
from lean_spec.subspecs.networking.transport.noise.types import CipherState


def _test_remote_static() -> x25519.X25519PublicKey:
    """Create a test X25519 public key for NoiseSession tests."""
    return x25519.X25519PrivateKey.from_private_bytes(bytes(32)).public_key()


def _test_remote_identity() -> bytes:
    """Create a test secp256k1 compressed public key for NoiseSession tests."""
    # A valid 33-byte compressed secp256k1 public key (starts with 0x02 or 0x03)
    return bytes([0x02] + [0] * 32)


class TestSessionConstants:
    """Tests for session constants."""

    def test_max_message_size(self) -> None:
        """Maximum message size is 65535 bytes (2-byte length prefix max)."""
        assert MAX_MESSAGE_SIZE == 65535

    def test_auth_tag_size(self) -> None:
        """ChaCha20-Poly1305 auth tag is 16 bytes."""
        assert AUTH_TAG_SIZE == 16

    def test_max_plaintext_size(self) -> None:
        """Maximum plaintext is message size minus auth tag."""
        assert MAX_PLAINTEXT_SIZE == MAX_MESSAGE_SIZE - AUTH_TAG_SIZE
        assert MAX_PLAINTEXT_SIZE == 65519


class TestNoiseSessionWrite:
    """Tests for NoiseSession.write()."""

    def test_write_encrypts_and_sends(self) -> None:
        """Write encrypts plaintext and sends with length prefix."""

        async def run_test() -> bytes:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            key = CipherKey(bytes(32))
            send_cipher = CipherState(key=key)
            recv_cipher = CipherState(key=key)

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=send_cipher,
                _recv_cipher=recv_cipher,
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            await session.write(b"hello")
            return writer.get_data()

        data = asyncio.run(run_test())

        # Should have 2-byte length prefix + encrypted data
        assert len(data) > 2

        # Length prefix should indicate ciphertext size
        length = struct.unpack(">H", data[:2])[0]
        assert length == len(data) - 2
        assert length == 5 + AUTH_TAG_SIZE  # "hello" + tag

    def test_write_empty_message(self) -> None:
        """Write can send empty plaintext."""

        async def run_test() -> bytes:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            key = CipherKey(bytes(32))
            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=key),
                _recv_cipher=CipherState(key=key),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            await session.write(b"")
            return writer.get_data()

        data = asyncio.run(run_test())

        # Empty plaintext produces just the auth tag
        length = struct.unpack(">H", data[:2])[0]
        assert length == AUTH_TAG_SIZE

    def test_write_closed_session_raises(self) -> None:
        """Writing to closed session raises SessionError."""

        async def run_test() -> None:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=CipherKey(bytes(32))),
                _recv_cipher=CipherState(key=CipherKey(bytes(32))),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            session._closed = True

            with pytest.raises(SessionError, match="closed"):
                await session.write(b"test")

        asyncio.run(run_test())

    def test_write_message_too_large_raises(self) -> None:
        """Writing message larger than MAX_PLAINTEXT_SIZE raises SessionError."""

        async def run_test() -> None:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=CipherKey(bytes(32))),
                _recv_cipher=CipherState(key=CipherKey(bytes(32))),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            large_data = bytes(MAX_PLAINTEXT_SIZE + 1)

            with pytest.raises(SessionError, match="too large"):
                await session.write(large_data)

        asyncio.run(run_test())

    def test_write_max_size_message_succeeds(self) -> None:
        """Writing exactly MAX_PLAINTEXT_SIZE bytes succeeds."""

        async def run_test() -> None:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=CipherKey(bytes(32))),
                _recv_cipher=CipherState(key=CipherKey(bytes(32))),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            max_data = bytes(MAX_PLAINTEXT_SIZE)
            await session.write(max_data)  # Should not raise

        asyncio.run(run_test())

    def test_write_increments_nonce(self) -> None:
        """Each write increments the send cipher nonce."""

        async def run_test() -> int:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            key = CipherKey(bytes(32))
            send_cipher = CipherState(key=key)

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=send_cipher,
                _recv_cipher=CipherState(key=key),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            assert send_cipher.nonce == 0
            await session.write(b"first")
            assert send_cipher.nonce == 1
            await session.write(b"second")
            return send_cipher.nonce

        nonce = asyncio.run(run_test())
        assert nonce == 2


class TestNoiseSessionRead:
    """Tests for NoiseSession.read()."""

    def test_read_decrypts_received_data(self) -> None:
        """Read decrypts data from the stream."""

        async def run_test() -> bytes:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            key = CipherKey(bytes(32))
            # Use separate cipher states to simulate send/receive
            encrypt_cipher = CipherState(key=key)
            decrypt_cipher = CipherState(key=key)

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=key),
                _recv_cipher=decrypt_cipher,
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            # Simulate incoming encrypted message
            plaintext = b"hello from peer"
            ciphertext = encrypt_cipher.encrypt_with_ad(b"", plaintext)
            length_prefix = struct.pack(">H", len(ciphertext))
            reader.feed_data(length_prefix + ciphertext)

            return await session.read()

        result = asyncio.run(run_test())
        assert result == b"hello from peer"

    def test_read_closed_session_raises(self) -> None:
        """Reading from closed session raises SessionError."""

        async def run_test() -> None:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=CipherKey(bytes(32))),
                _recv_cipher=CipherState(key=CipherKey(bytes(32))),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            session._closed = True

            with pytest.raises(SessionError, match="closed"):
                await session.read()

        asyncio.run(run_test())

    def test_read_connection_closed_raises(self) -> None:
        """Reading when connection is closed raises SessionError."""

        async def run_test() -> None:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=CipherKey(bytes(32))),
                _recv_cipher=CipherState(key=CipherKey(bytes(32))),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            # Signal EOF
            reader.feed_eof()

            with pytest.raises(SessionError, match="closed by peer"):
                await session.read()

        asyncio.run(run_test())

    def test_read_zero_length_raises(self) -> None:
        """Zero-length message raises SessionError."""

        async def run_test() -> None:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=CipherKey(bytes(32))),
                _recv_cipher=CipherState(key=CipherKey(bytes(32))),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            # Feed zero-length message
            reader.feed_data(b"\x00\x00")

            with pytest.raises(SessionError, match="zero-length"):
                await session.read()

        asyncio.run(run_test())

    def test_read_message_too_large_raises(self) -> None:
        """Message larger than MAX_MESSAGE_SIZE raises SessionError."""
        # Note: With a 2-byte big-endian length prefix, the maximum value is 65535,
        # which equals MAX_MESSAGE_SIZE. So we can't actually exceed it via the
        # length prefix. This test documents that the wire format inherently
        # prevents oversized messages.
        #
        # The length check in read() still guards against implementation bugs
        # if the constant were ever changed.
        pass

    def test_read_increments_nonce(self) -> None:
        """Each read increments the receive cipher nonce."""

        async def run_test() -> int:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            key = CipherKey(bytes(32))
            encrypt_cipher = CipherState(key=key)
            recv_cipher = CipherState(key=key)

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=key),
                _recv_cipher=recv_cipher,
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            # Feed two encrypted messages
            for msg in [b"first", b"second"]:
                ciphertext = encrypt_cipher.encrypt_with_ad(b"", msg)
                length_prefix = struct.pack(">H", len(ciphertext))
                reader.feed_data(length_prefix + ciphertext)

            assert recv_cipher.nonce == 0
            await session.read()
            assert recv_cipher.nonce == 1
            await session.read()
            return recv_cipher.nonce

        nonce = asyncio.run(run_test())
        assert nonce == 2


class TestNoiseSessionClose:
    """Tests for NoiseSession.close()."""

    def test_close_sets_closed_flag(self) -> None:
        """Close sets the _closed flag."""

        async def run_test() -> bool:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=CipherKey(bytes(32))),
                _recv_cipher=CipherState(key=CipherKey(bytes(32))),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            assert not session.is_closed
            await session.close()
            return session.is_closed

        assert asyncio.run(run_test()) is True

    def test_close_is_idempotent(self) -> None:
        """Calling close multiple times is safe."""

        async def run_test() -> None:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=CipherKey(bytes(32))),
                _recv_cipher=CipherState(key=CipherKey(bytes(32))),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            await session.close()
            await session.close()  # Should not raise

        asyncio.run(run_test())

    def test_close_closes_writer(self) -> None:
        """Close closes the underlying writer."""

        async def run_test() -> bool:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=CipherKey(bytes(32))),
                _recv_cipher=CipherState(key=CipherKey(bytes(32))),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            await session.close()
            return writer._closed

        assert asyncio.run(run_test()) is True


class TestNoiseSessionRoundtrip:
    """Tests for full encrypt/decrypt roundtrips."""

    def test_roundtrip_simple_message(self) -> None:
        """Write then read produces original plaintext."""

        async def run_test() -> bytes:
            # Create a pair of sessions that can communicate
            key = CipherKey(bytes(32))

            # Session A sends to Session B
            reader_a = asyncio.StreamReader()
            writer_a = MockStreamWriter()
            session_a = NoiseSession(
                reader=reader_a,
                writer=writer_a,
                _send_cipher=CipherState(key=key),
                _recv_cipher=CipherState(key=key),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            # Session A writes
            await session_a.write(b"test message")

            # Feed the output to session B's reader
            reader_b = asyncio.StreamReader()
            reader_b.feed_data(writer_a.get_data())

            session_b = NoiseSession(
                reader=reader_b,
                writer=MockStreamWriter(),
                _send_cipher=CipherState(key=key),
                _recv_cipher=CipherState(key=key),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            return await session_b.read()

        result = asyncio.run(run_test())
        assert result == b"test message"

    def test_roundtrip_multiple_messages(self) -> None:
        """Multiple writes and reads work correctly."""

        async def run_test() -> list[bytes]:
            key = CipherKey(bytes(32))

            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            # Both ciphers need to track the same nonce progression
            send_cipher = CipherState(key=key)
            recv_cipher = CipherState(key=key)

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=send_cipher,
                _recv_cipher=recv_cipher,
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            messages = [b"one", b"two", b"three"]

            # Write all messages
            for msg in messages:
                await session.write(msg)

            # Reset recv cipher to match send progression
            # and feed the written data back
            recv_cipher_for_read = CipherState(key=key)
            reader.feed_data(writer.get_data())

            session2 = NoiseSession(
                reader=reader,
                writer=MockStreamWriter(),
                _send_cipher=CipherState(key=key),
                _recv_cipher=recv_cipher_for_read,
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            # Read all messages back
            results = []
            for _ in messages:
                results.append(await session2.read())

            return results

        results = asyncio.run(run_test())
        assert results == [b"one", b"two", b"three"]


class TestHandshakeMessageHelpers:
    """Tests for handshake message helpers."""

    def test_send_handshake_message_format(self) -> None:
        """Handshake message has 2-byte big-endian length prefix."""

        async def run_test() -> bytes:
            writer = MockStreamWriter()
            await _send_handshake_message(writer, b"test message")
            return writer.get_data()

        data = asyncio.run(run_test())

        # Length prefix (2 bytes, big-endian) + message
        assert data[:2] == b"\x00\x0c"  # 12 bytes
        assert data[2:] == b"test message"

    def test_send_handshake_message_empty(self) -> None:
        """Empty handshake message has zero length prefix."""

        async def run_test() -> bytes:
            writer = MockStreamWriter()
            await _send_handshake_message(writer, b"")
            return writer.get_data()

        data = asyncio.run(run_test())
        assert data == b"\x00\x00"

    def test_recv_handshake_message(self) -> None:
        """Receive handshake message with length prefix."""

        async def run_test() -> bytes:
            reader = asyncio.StreamReader()
            # Feed: 2-byte length prefix + message
            reader.feed_data(b"\x00\x05hello")
            return await _recv_handshake_message(reader)

        result = asyncio.run(run_test())
        assert result == b"hello"

    def test_recv_handshake_message_large(self) -> None:
        """Receive larger handshake message."""

        async def run_test() -> bytes:
            reader = asyncio.StreamReader()
            # 256-byte message
            message = bytes(256)
            length_prefix = struct.pack(">H", 256)
            reader.feed_data(length_prefix + message)
            return await _recv_handshake_message(reader)

        result = asyncio.run(run_test())
        assert len(result) == 256

    def test_send_recv_roundtrip(self) -> None:
        """Send and receive roundtrip preserves message."""

        async def run_test() -> bytes:
            writer = MockStreamWriter()
            original = b"handshake payload data"
            await _send_handshake_message(writer, original)

            reader = asyncio.StreamReader()
            reader.feed_data(writer.get_data())
            return await _recv_handshake_message(reader)

        result = asyncio.run(run_test())
        assert result == b"handshake payload data"


class TestNoiseSessionProperties:
    """Tests for NoiseSession properties."""

    def test_is_closed_initially_false(self) -> None:
        """is_closed is False for new session."""

        async def run_test() -> bool:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=CipherKey(bytes(32))),
                _recv_cipher=CipherState(key=CipherKey(bytes(32))),
                remote_static=_test_remote_static(),
                remote_identity=_test_remote_identity(),
            )

            return session.is_closed

        assert asyncio.run(run_test()) is False

    def test_remote_static_stored(self) -> None:
        """remote_static stores peer's public key."""

        async def run_test() -> bytes:
            reader = asyncio.StreamReader()
            writer = MockStreamWriter()

            remote_key = x25519.X25519PrivateKey.from_private_bytes(bytes(range(32))).public_key()
            session = NoiseSession(
                reader=reader,
                writer=writer,
                _send_cipher=CipherState(key=CipherKey(bytes(32))),
                _recv_cipher=CipherState(key=CipherKey(bytes(32))),
                remote_static=remote_key,
                remote_identity=_test_remote_identity(),
            )

            return session.remote_static.public_bytes_raw()

        # Verify the key bytes match (derive public key from the same private key bytes)
        expected_pub = (
            x25519.X25519PrivateKey.from_private_bytes(bytes(range(32)))
            .public_key()
            .public_bytes_raw()
        )
        assert asyncio.run(run_test()) == expected_pub


# Helper class for testing
class MockStreamWriter:
    """Mock StreamWriter for testing."""

    def __init__(self) -> None:
        self._data = bytearray()
        self._closed = False

    def write(self, data: bytes) -> None:
        self._data.extend(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self._closed = True

    async def wait_closed(self) -> None:
        pass

    def get_data(self) -> bytes:
        return bytes(self._data)
