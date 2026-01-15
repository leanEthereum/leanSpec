"""
Noise XX handshake implementation for libp2p.

The XX pattern provides mutual authentication with forward secrecy.
Neither party needs to know the other's identity beforehand.

Handshake flow:
    -> e                 # Message 1: Initiator sends ephemeral pubkey
    <- e, ee, s, es      # Message 2: Responder ephemeral + DH + static + DH
    -> s, se             # Message 3: Initiator static + DH

After handshake:
    - Both parties know each other's static public key
    - Two cipher states derived for bidirectional encryption
    - Forward secrecy: compromising static keys doesn't reveal past sessions

libp2p extensions:
    - Static keys are X25519 (not secp256k1)
    - Handshake payloads contain libp2p identity protobuf
    - PeerId derived from secp256k1 identity key in payload

Wire format:
    Each handshake message is length-prefixed (2-byte big-endian).
    Message 1: [32-byte ephemeral pubkey]
    Message 2: [32-byte ephemeral][48-byte encrypted static][payload...]
    Message 3: [48-byte encrypted static][payload...]

The 48-byte encrypted static = 32-byte key + 16-byte auth tag.

References:
    - https://noiseprotocol.org/noise.html
    - https://github.com/libp2p/specs/blob/master/noise/README.md
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, auto

from cryptography.hazmat.primitives.asymmetric import x25519

from .crypto import generate_keypair, x25519_dh
from .types import CipherState, SymmetricState


class HandshakeRole(IntEnum):
    """Role in the handshake - determines message order."""

    INITIATOR = auto()
    """Client/dialer - sends first message."""

    RESPONDER = auto()
    """Server/listener - responds to first message."""


class HandshakeState(IntEnum):
    """State machine states for XX handshake."""

    INITIALIZED = auto()
    """Initial state, ready to start."""

    AWAITING_MESSAGE_1 = auto()
    """Responder waiting for initiator's first message."""

    AWAITING_MESSAGE_2 = auto()
    """Initiator waiting for responder's reply."""

    AWAITING_MESSAGE_3 = auto()
    """Responder waiting for initiator's final message."""

    COMPLETE = auto()
    """Handshake finished successfully."""


class NoiseError(Exception):
    """Raised when handshake fails."""


@dataclass(slots=True)
class NoiseHandshake:
    """
    XX handshake state machine.

    Usage for initiator:
        handshake = NoiseHandshake.initiator(static_key)
        msg1 = handshake.write_message_1()
        # send msg1, receive msg2
        payload2 = handshake.read_message_2(msg2)
        msg3 = handshake.write_message_3(our_payload)
        # send msg3
        send_cipher, recv_cipher = handshake.finalize()

    Usage for responder:
        handshake = NoiseHandshake.responder(static_key)
        # receive msg1
        handshake.read_message_1(msg1)
        msg2 = handshake.write_message_2(our_payload)
        # send msg2, receive msg3
        payload3 = handshake.read_message_3(msg3)
        recv_cipher, send_cipher = handshake.finalize()

    Note: Initiator and responder get ciphers in opposite order!
    """

    role: HandshakeRole
    """Our role in the handshake."""

    local_static: x25519.X25519PrivateKey
    """Our long-term identity key."""

    local_static_public: x25519.X25519PublicKey
    """Our static public key."""

    local_ephemeral: x25519.X25519PrivateKey = field(repr=False)
    """Fresh ephemeral key for this handshake."""

    local_ephemeral_public: x25519.X25519PublicKey = field(repr=False)
    """Our ephemeral public key."""

    remote_static_public: x25519.X25519PublicKey | None = None
    """Peer's static public key, learned during handshake."""

    remote_ephemeral_public: x25519.X25519PublicKey | None = None
    """Peer's ephemeral public key, learned during handshake."""

    _symmetric_state: SymmetricState = field(default_factory=SymmetricState)
    """Internal symmetric state for key derivation."""

    _state: HandshakeState = HandshakeState.INITIALIZED
    """Current state machine state."""

    @classmethod
    def initiator(cls, static_key: x25519.X25519PrivateKey) -> NoiseHandshake:
        """
        Create handshake as initiator (client/dialer).

        Args:
            static_key: Our long-term X25519 identity key

        Returns:
            Handshake ready to call write_message_1()
        """
        ephemeral, ephemeral_public = generate_keypair()

        return cls(
            role=HandshakeRole.INITIATOR,
            local_static=static_key,
            local_static_public=static_key.public_key(),
            local_ephemeral=ephemeral,
            local_ephemeral_public=ephemeral_public,
        )

    @classmethod
    def responder(cls, static_key: x25519.X25519PrivateKey) -> NoiseHandshake:
        """
        Create handshake as responder (server/listener).

        Args:
            static_key: Our long-term X25519 identity key

        Returns:
            Handshake ready to call read_message_1()
        """
        ephemeral, ephemeral_public = generate_keypair()

        handshake = cls(
            role=HandshakeRole.RESPONDER,
            local_static=static_key,
            local_static_public=static_key.public_key(),
            local_ephemeral=ephemeral,
            local_ephemeral_public=ephemeral_public,
        )
        handshake._state = HandshakeState.AWAITING_MESSAGE_1
        return handshake

    def write_message_1(self) -> bytes:
        """
        Initiator: write first handshake message.

        Pattern: -> e

        Returns:
            32-byte message containing our ephemeral public key

        This message is sent in cleartext. It establishes the
        ephemeral key that will be used for forward secrecy.
        """
        if self.role != HandshakeRole.INITIATOR:
            raise NoiseError("Only initiator writes message 1")
        if self._state != HandshakeState.INITIALIZED:
            raise NoiseError(f"Invalid state for write_message_1: {self._state}")

        # Token "e": send our ephemeral pubkey.
        #
        # Fresh key generated for this handshake.
        # Provides forward secrecy: past sessions remain secure
        # even if static key is later compromised.
        #
        # mix_hash binds pubkey to transcript.
        # Prevents attacker from substituting different key later.
        ephemeral_bytes = self.local_ephemeral_public.public_bytes_raw()
        self._symmetric_state.mix_hash(ephemeral_bytes)

        self._state = HandshakeState.AWAITING_MESSAGE_2
        return ephemeral_bytes

    def read_message_1(self, message: bytes) -> None:
        """
        Responder: read first handshake message.

        Pattern: -> e (from initiator)

        Args:
            message: 32-byte message from initiator

        Raises:
            NoiseError: If message is wrong size or state is invalid
        """
        if self.role != HandshakeRole.RESPONDER:
            raise NoiseError("Only responder reads message 1")
        if self._state != HandshakeState.AWAITING_MESSAGE_1:
            raise NoiseError(f"Invalid state for read_message_1: {self._state}")
        if len(message) != 32:
            raise NoiseError(f"Message 1 must be 32 bytes, got {len(message)}")

        # Token "e": receive initiator's ephemeral pubkey.
        # Store for DH operations in message 2.
        self.remote_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(message)

        # Mix into transcript for binding.
        # Both parties mix same data in same order -> derive identical keys.
        # Any tampering will cause key mismatch.
        self._symmetric_state.mix_hash(message)

        self._state = HandshakeState.INITIALIZED  # Ready for write_message_2

    def write_message_2(self, payload: bytes = b"") -> bytes:
        """
        Responder: write second handshake message.

        Pattern: <- e, ee, s, es

        Args:
            payload: Optional payload to encrypt (libp2p identity)

        Returns:
            Message: ephemeral + encrypted(static) + encrypted(payload)

        This message:
            1. Sends our ephemeral key (cleartext)
            2. Performs ee DH (mixes in shared secret)
            3. Sends our static key (now encrypted)
            4. Performs es DH (mixes in another secret)
            5. Sends optional payload (encrypted)
        """
        if self.role != HandshakeRole.RESPONDER:
            raise NoiseError("Only responder writes message 2")
        if self._state != HandshakeState.INITIALIZED:
            raise NoiseError(f"Invalid state for write_message_2: {self._state}")
        if self.remote_ephemeral_public is None:
            raise NoiseError("Must read message 1 before writing message 2")

        parts: list[bytes] = []

        # Token "e": send our ephemeral pubkey in cleartext.
        # Both parties now have each other's ephemeral keys.
        ephemeral_bytes = self.local_ephemeral_public.public_bytes_raw()
        parts.append(ephemeral_bytes)
        self._symmetric_state.mix_hash(ephemeral_bytes)

        # Token "ee": first DH - DH(our_ephemeral, their_ephemeral).
        #
        # Creates shared secret from fresh keys.
        # Provides forward secrecy: compromising static keys later
        # cannot reveal this session's keys.
        #
        # After mix_key, we have an encryption key.
        ee = x25519_dh(self.local_ephemeral, self.remote_ephemeral_public)
        self._symmetric_state.mix_key(ee)

        # Token "s": send our static pubkey (now encrypted).
        #
        # Static key reveals identity.
        # Encrypting hides us from passive observers.
        # Only the initiator (who shares ee secret) can decrypt.
        static_bytes = self.local_static_public.public_bytes_raw()
        encrypted_static = self._symmetric_state.encrypt_and_hash(static_bytes)
        parts.append(encrypted_static)

        # Token "es": second DH - DH(our_static, their_ephemeral).
        #
        # Binds our long-term identity to the session.
        # Provides "responder authentication":
        # - Initiator verifies we control the static key we sent.
        # - Attacker cannot impersonate without our static private key.
        es = x25519_dh(self.local_static, self.remote_ephemeral_public)
        self._symmetric_state.mix_key(es)

        # Encrypt optional payload (e.g., libp2p signed identity).
        # Encrypted under key derived from both ee and es.
        if payload:
            encrypted_payload = self._symmetric_state.encrypt_and_hash(payload)
            parts.append(encrypted_payload)

        self._state = HandshakeState.AWAITING_MESSAGE_3
        return b"".join(parts)

    def read_message_2(self, message: bytes) -> bytes:
        """
        Initiator: read second handshake message.

        Pattern: <- e, ee, s, es (from responder)

        Args:
            message: Responder's message 2

        Returns:
            Decrypted payload from responder

        Raises:
            NoiseError: If message is malformed
            InvalidTag: If decryption fails (indicates attack or bug)
        """
        if self.role != HandshakeRole.INITIATOR:
            raise NoiseError("Only initiator reads message 2")
        if self._state != HandshakeState.AWAITING_MESSAGE_2:
            raise NoiseError(f"Invalid state for read_message_2: {self._state}")

        # Minimum size: 32 (ephemeral) + 48 (encrypted static = 32 key + 16 auth tag).
        if len(message) < 80:
            raise NoiseError(f"Message 2 too short: {len(message)} < 80")

        offset = 0

        # Token "e": receive responder's ephemeral pubkey.
        ephemeral_bytes = message[offset : offset + 32]
        self.remote_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_bytes)
        self._symmetric_state.mix_hash(ephemeral_bytes)
        offset += 32

        # Token "ee": DH(our_ephemeral, their_ephemeral).
        #
        # DH magic: DH(a, B) = DH(b, A).
        # We compute same shared secret as responder.
        ee = x25519_dh(self.local_ephemeral, self.remote_ephemeral_public)
        self._symmetric_state.mix_key(ee)

        # Token "s": receive responder's static pubkey (encrypted).
        #
        # 48 bytes = 32 key + 16 auth tag.
        # Auth tag verifies no tampering.
        # Decryption failure means:
        # - Attacker modified message, OR
        # - Protocol bug caused key mismatch
        encrypted_static = message[offset : offset + 48]
        static_bytes = self._symmetric_state.decrypt_and_hash(encrypted_static)
        self.remote_static_public = x25519.X25519PublicKey.from_public_bytes(static_bytes)
        offset += 48

        # Token "es": DH(our_ephemeral, their_static).
        #
        # Note: we use OUR EPHEMERAL with THEIR STATIC.
        # Responder computed DH(their_static, our_ephemeral) - same result.
        #
        # Proves responder controls the static key they sent.
        # Attacker cannot compute without responder's private key.
        es = x25519_dh(self.local_ephemeral, self.remote_static_public)
        self._symmetric_state.mix_key(es)

        # Decrypt optional payload (libp2p signed identity).
        # Success proves responder knows both private keys.
        # Completes responder authentication.
        payload = b""
        if offset < len(message):
            encrypted_payload = message[offset:]
            payload = self._symmetric_state.decrypt_and_hash(encrypted_payload)

        self._state = HandshakeState.INITIALIZED  # Ready for write_message_3
        return payload

    def write_message_3(self, payload: bytes = b"") -> bytes:
        """
        Initiator: write third (final) handshake message.

        Pattern: -> s, se

        Args:
            payload: Optional payload to encrypt (libp2p identity)

        Returns:
            Message: encrypted(static) + encrypted(payload)
        """
        if self.role != HandshakeRole.INITIATOR:
            raise NoiseError("Only initiator writes message 3")
        if self._state != HandshakeState.INITIALIZED:
            raise NoiseError(f"Invalid state for write_message_3: {self._state}")
        if self.remote_ephemeral_public is None:
            raise NoiseError("Must read message 2 before writing message 3")

        parts: list[bytes] = []

        # Token "s": send our static pubkey (encrypted).
        # Encrypted under key from ee + es.
        # Only responder can decrypt. Completes identity exchange.
        static_bytes = self.local_static_public.public_bytes_raw()
        encrypted_static = self._symmetric_state.encrypt_and_hash(static_bytes)
        parts.append(encrypted_static)

        # Token "se": final DH - DH(our_static, their_ephemeral).
        #
        # Mirror of responder's es operation.
        # We use OUR STATIC with THEIR EPHEMERAL.
        # Responder computes DH(their_ephemeral, our_static) - same result.
        #
        # Proves we control the static key we sent.
        #
        # Session key now depends on ALL THREE DH operations:
        # - ee: forward secrecy (both ephemerals)
        # - es: authenticates responder
        # - se: authenticates initiator
        se = x25519_dh(self.local_static, self.remote_ephemeral_public)
        self._symmetric_state.mix_key(se)

        # Encrypt optional payload (libp2p signed identity).
        if payload:
            encrypted_payload = self._symmetric_state.encrypt_and_hash(payload)
            parts.append(encrypted_payload)

        self._state = HandshakeState.COMPLETE
        return b"".join(parts)

    def read_message_3(self, message: bytes) -> bytes:
        """
        Responder: read third (final) handshake message.

        Pattern: -> s, se (from initiator)

        Args:
            message: Initiator's message 3

        Returns:
            Decrypted payload from initiator
        """
        if self.role != HandshakeRole.RESPONDER:
            raise NoiseError("Only responder reads message 3")
        if self._state != HandshakeState.AWAITING_MESSAGE_3:
            raise NoiseError(f"Invalid state for read_message_3: {self._state}")

        # Minimum size: 48 (encrypted static = 32 bytes + 16 auth tag).
        if len(message) < 48:
            raise NoiseError(f"Message 3 too short: {len(message)} < 48")

        offset = 0

        # Token "s": receive initiator's static pubkey (encrypted).
        # Success proves they knew correct ee and es secrets.
        encrypted_static = message[offset : offset + 48]
        static_bytes = self._symmetric_state.decrypt_and_hash(encrypted_static)
        self.remote_static_public = x25519.X25519PublicKey.from_public_bytes(static_bytes)
        offset += 48

        # Token "se": DH(our_ephemeral, their_static).
        #
        # We use OUR EPHEMERAL with THEIR STATIC.
        # Initiator computed DH(their_static, our_ephemeral) - same result.
        #
        # Authenticates initiator: only static key holder can compute this.
        # Handshake complete. Session key depends on all three DH secrets.
        se = x25519_dh(self.local_ephemeral, self.remote_static_public)
        self._symmetric_state.mix_key(se)

        # Decrypt optional payload (libp2p signed identity).
        # Proves initiator completed all three DH operations.
        payload = b""
        if offset < len(message):
            encrypted_payload = message[offset:]
            payload = self._symmetric_state.decrypt_and_hash(encrypted_payload)

        self._state = HandshakeState.COMPLETE
        return payload

    def finalize(self) -> tuple[CipherState, CipherState]:
        """
        Derive final transport cipher states.

        Must be called after handshake completes.

        Returns:
            (send_cipher, recv_cipher) for this party

        Note: Initiator and responder receive ciphers in opposite order!
            - Initiator: (cipher1, cipher2) = (send, recv)
            - Responder: (cipher1, cipher2) = (recv, send)
        """
        if self._state != HandshakeState.COMPLETE:
            raise NoiseError(f"Handshake not complete: {self._state}")

        # Key splitting (Noise spec section 5.2).
        #
        # Derive two transport keys from final chaining key.
        # Separate key per direction prevents reflection attacks.
        cipher1, cipher2 = self._symmetric_state.split()

        # split() returns keys in fixed order.
        # Initiator and responder use OPPOSITE directions:
        # - cipher1: initiator -> responder
        # - cipher2: responder -> initiator
        if self.role == HandshakeRole.INITIATOR:
            return cipher1, cipher2  # (send, recv)
        else:
            return cipher2, cipher1  # (send, recv) - swapped!
