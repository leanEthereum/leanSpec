"""
Encrypted transport session after Noise handshake.

After the XX handshake completes, both parties have derived cipher
states for bidirectional communication. This module wraps those
ciphers in an async-friendly session interface.

Wire format (post-handshake):
    [2-byte length (big-endian)][encrypted payload]

The length prefix is NOT encrypted. It contains the size of the
encrypted payload including the 16-byte auth tag.

Maximum message size: 65535 bytes (limited by 2-byte length)
Maximum plaintext per message: 65535 - 16 = 65519 bytes

Messages larger than this must be fragmented at a higher layer
(e.g., by the multiplexer).

References:
    - https://github.com/libp2p/specs/blob/master/noise/README.md#wire-format
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import x25519

from ..identity import IdentityKeypair
from ..protocols import StreamReaderProtocol, StreamWriterProtocol
from .payload import NoiseIdentityPayload
from .types import CipherState

MAX_MESSAGE_SIZE: int = 65535
"""Maximum encrypted message size including 16-byte auth tag."""

AUTH_TAG_SIZE: int = 16
"""ChaCha20-Poly1305 authentication tag overhead."""

MAX_PLAINTEXT_SIZE: int = MAX_MESSAGE_SIZE - AUTH_TAG_SIZE
"""Maximum plaintext size per message (65535 - 16 = 65519 bytes)."""


class SessionError(Exception):
    """Raised when session operations fail."""


@dataclass(slots=True)
class NoiseSession:
    """
    Bidirectional encrypted channel over TCP.

    After Noise handshake completes, this class handles all further
    communication. Messages are encrypted, length-prefixed, and
    authenticated.

    Thread safety: NOT thread-safe. Use asyncio synchronization if
    concurrent reads/writes are needed (though typically the multiplexer
    handles concurrency).

    Usage:
        session = NoiseSession(reader, writer, send_cipher, recv_cipher, remote_pk, identity)
        await session.write(b"hello")
        response = await session.read()
        await session.close()
    """

    reader: StreamReaderProtocol
    """Underlying TCP read stream."""

    writer: StreamWriterProtocol
    """Underlying TCP write stream."""

    _send_cipher: CipherState = field(repr=False)
    """Cipher for encrypting outbound messages."""

    _recv_cipher: CipherState = field(repr=False)
    """Cipher for decrypting inbound messages."""

    remote_static: x25519.X25519PublicKey
    """Peer's X25519 Noise static public key from handshake."""

    remote_identity: bytes
    """
    Peer's secp256k1 identity public key (33 bytes compressed).

    This is extracted from the identity payload during handshake and
    verified via ECDSA signature. Use this to derive the remote PeerId.
    """

    _closed: bool = field(default=False, repr=False)
    """Whether the session has been closed."""

    async def write(self, plaintext: bytes) -> None:
        """
        Encrypt and send a message.

        The message is encrypted, then length-prefixed with 2-byte
        big-endian length, then written to the underlying stream.

        Args:
            plaintext: Data to send (max 65519 bytes)

        Raises:
            SessionError: If message too large or session closed
            ConnectionError: If underlying connection fails
        """
        if self._closed:
            raise SessionError("Session is closed")

        if len(plaintext) > MAX_PLAINTEXT_SIZE:
            raise SessionError(f"Message too large: {len(plaintext)} > {MAX_PLAINTEXT_SIZE}")

        # Encrypt with empty associated data (per libp2p spec)
        ciphertext = self._send_cipher.encrypt_with_ad(b"", plaintext)

        # Length prefix (2-byte big-endian)
        length_prefix = struct.pack(">H", len(ciphertext))

        # Write atomically
        self.writer.write(length_prefix + ciphertext)
        await self.writer.drain()

    async def read(self) -> bytes:
        """
        Read and decrypt a message.

        Reads the 2-byte length prefix, then reads that many bytes
        of ciphertext, then decrypts and returns the plaintext.

        Returns:
            Decrypted plaintext

        Raises:
            SessionError: If session closed or EOF reached unexpectedly
            cryptography.exceptions.InvalidTag: If decryption fails
            ConnectionError: If underlying connection fails
        """
        if self._closed:
            raise SessionError("Session is closed")

        # Read 2-byte length prefix
        length_bytes = await self._read_exact(2)
        if not length_bytes:
            raise SessionError("Connection closed by peer")

        length = struct.unpack(">H", length_bytes)[0]

        if length == 0:
            raise SessionError("Invalid zero-length message")

        if length > MAX_MESSAGE_SIZE:
            raise SessionError(f"Message too large: {length} > {MAX_MESSAGE_SIZE}")

        # Read ciphertext
        ciphertext = await self._read_exact(length)
        if len(ciphertext) != length:
            raise SessionError(f"Short read: expected {length}, got {len(ciphertext)}")

        # Decrypt with empty associated data
        plaintext = self._recv_cipher.decrypt_with_ad(b"", ciphertext)
        return plaintext

    async def _read_exact(self, n: int) -> bytes:
        """
        Read exactly n bytes from the stream.

        Args:
            n: Number of bytes to read

        Returns:
            Exactly n bytes, or fewer if EOF reached

        Raises:
            SessionError: If session closed
        """
        data = await self.reader.read(n)
        # StreamReader.read returns partial data on EOF
        # We need to handle short reads by reading more
        while len(data) < n:
            more = await self.reader.read(n - len(data))
            if not more:
                # EOF reached
                break
            data += more
        return data

    async def close(self) -> None:
        """
        Close the session and underlying connection.

        This is a graceful close - it waits for pending writes to flush.
        After close, read/write will raise SessionError.
        """
        if self._closed:
            return

        self._closed = True
        self.writer.close()
        await self.writer.wait_closed()

    @property
    def is_closed(self) -> bool:
        """Check if session has been closed."""
        return self._closed


async def perform_handshake_initiator(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    noise_key: x25519.X25519PrivateKey,
    identity_key: IdentityKeypair,
) -> NoiseSession:
    """
    Perform Noise XX handshake as initiator (client) with identity binding.

    The handshake exchanges identity payloads that bind each peer's secp256k1
    identity key to their X25519 Noise key. This allows deriving the remote
    PeerId from their verified identity key.

    Args:
        reader: TCP stream reader
        writer: TCP stream writer
        noise_key: Our X25519 Noise static key
        identity_key: Our secp256k1 identity keypair

    Returns:
        Established NoiseSession with verified remote identity

    Raises:
        NoiseError: If handshake fails
        SessionError: If identity verification fails
        InvalidTag: If decryption fails (indicates MITM or bug)
    """
    from .handshake import NoiseHandshake

    handshake = NoiseHandshake.initiator(noise_key)

    # Message 1: -> e
    msg1 = handshake.write_message_1()
    await _send_handshake_message(writer, msg1)

    # Message 2: <- e, ee, s, es + identity payload
    msg2 = await _recv_handshake_message(reader)
    payload2 = handshake.read_message_2(msg2)

    # Verify responder's identity
    if not payload2:
        raise SessionError("Responder did not send identity payload")

    remote_payload = NoiseIdentityPayload.decode(payload2)

    # After reading msg2, we have responder's Noise static key
    if handshake.remote_static_public is None:
        raise SessionError("Remote static key not established")
    remote_noise_pubkey = handshake.remote_static_public.public_bytes_raw()

    if not remote_payload.verify(remote_noise_pubkey):
        raise SessionError("Invalid remote identity signature")

    remote_identity = remote_payload.extract_public_key()
    if remote_identity is None:
        raise SessionError("Invalid remote identity key")

    # Create our identity payload for message 3
    our_noise_pubkey = noise_key.public_key().public_bytes_raw()
    our_payload = NoiseIdentityPayload.create(identity_key, our_noise_pubkey)

    # Message 3: -> s, se + our identity payload
    msg3 = handshake.write_message_3(our_payload.encode())
    await _send_handshake_message(writer, msg3)

    # Derive transport ciphers
    send_cipher, recv_cipher = handshake.finalize()

    return NoiseSession(
        reader=reader,
        writer=writer,
        _send_cipher=send_cipher,
        _recv_cipher=recv_cipher,
        remote_static=handshake.remote_static_public,
        remote_identity=remote_identity,
    )


async def perform_handshake_responder(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    noise_key: x25519.X25519PrivateKey,
    identity_key: IdentityKeypair,
) -> NoiseSession:
    """
    Perform Noise XX handshake as responder (server) with identity binding.

    The handshake exchanges identity payloads that bind each peer's secp256k1
    identity key to their X25519 Noise key. This allows deriving the remote
    PeerId from their verified identity key.

    Args:
        reader: TCP stream reader
        writer: TCP stream writer
        noise_key: Our X25519 Noise static key
        identity_key: Our secp256k1 identity keypair

    Returns:
        Established NoiseSession with verified remote identity

    Raises:
        NoiseError: If handshake fails
        SessionError: If identity verification fails
        InvalidTag: If decryption fails (indicates MITM or bug)
    """
    from .handshake import NoiseHandshake

    handshake = NoiseHandshake.responder(noise_key)

    # Message 1: -> e
    msg1 = await _recv_handshake_message(reader)
    handshake.read_message_1(msg1)

    # Create our identity payload for message 2
    our_noise_pubkey = noise_key.public_key().public_bytes_raw()
    our_payload = NoiseIdentityPayload.create(identity_key, our_noise_pubkey)

    # Message 2: <- e, ee, s, es + our identity payload
    msg2 = handshake.write_message_2(our_payload.encode())
    await _send_handshake_message(writer, msg2)

    # Message 3: -> s, se + identity payload
    msg3 = await _recv_handshake_message(reader)
    payload3 = handshake.read_message_3(msg3)

    # Verify initiator's identity
    if not payload3:
        raise SessionError("Initiator did not send identity payload")

    remote_payload = NoiseIdentityPayload.decode(payload3)

    # After reading msg3, we have initiator's Noise static key
    if handshake.remote_static_public is None:
        raise SessionError("Remote static key not established")
    remote_noise_pubkey = handshake.remote_static_public.public_bytes_raw()

    if not remote_payload.verify(remote_noise_pubkey):
        raise SessionError("Invalid remote identity signature")

    remote_identity = remote_payload.extract_public_key()
    if remote_identity is None:
        raise SessionError("Invalid remote identity key")

    # Derive transport ciphers
    send_cipher, recv_cipher = handshake.finalize()

    return NoiseSession(
        reader=reader,
        writer=writer,
        _send_cipher=send_cipher,
        _recv_cipher=recv_cipher,
        remote_static=handshake.remote_static_public,
        remote_identity=remote_identity,
    )


async def _send_handshake_message(writer: StreamWriterProtocol, message: bytes) -> None:
    """Send a handshake message with 2-byte length prefix."""
    length_prefix = struct.pack(">H", len(message))
    writer.write(length_prefix + message)
    await writer.drain()


async def _recv_handshake_message(reader: StreamReaderProtocol) -> bytes:
    """Receive a handshake message with 2-byte length prefix."""
    length_bytes = await reader.readexactly(2)
    length = struct.unpack(">H", length_bytes)[0]
    return await reader.readexactly(length)
