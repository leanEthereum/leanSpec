"""
Type definitions for Noise protocol.

The Noise protocol maintains several pieces of state during handshake:
    - CipherState: Encryption key + nonce counter for one direction
    - SymmetricState: Chaining key + hash + current cipher state
    - HandshakeState: Full handshake state including keys

After handshake completes, only two CipherStates remain (one per direction).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .constants import (
    MAX_NONCE,
    PROTOCOL_NAME_HASH,
    ChainingKey,
    CipherKey,
    HandshakeHash,
    SharedSecret,
)
from .crypto import decrypt, encrypt, hkdf_sha256, sha256


class CipherError(Exception):
    """Raised when cipher operations fail."""


@dataclass(slots=True)
class CipherState:
    """
    Encryption state for one direction of communication.

    Noise uses separate cipher states for sending and receiving.
    Each maintains:
        - A 32-byte symmetric key (k)
        - A 64-bit nonce counter (n)

    The nonce increments after each encrypt/decrypt operation.
    Nonce reuse would be catastrophic, so we track it carefully.

    After 2^64 messages in one direction, the connection must be
    rekeyed or closed. In practice, this limit is never reached.
    """

    key: CipherKey
    """32-byte ChaCha20-Poly1305 key."""

    nonce: int = 0
    """64-bit counter, increments after each operation."""

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext with associated data.

        Args:
            ad: Associated data (authenticated, not encrypted).
            plaintext: Data to encrypt.

        Returns:
            Ciphertext with 16-byte auth tag.

        Raises:
            CipherError: If nonce would overflow (2^64 messages sent).

        The nonce auto-increments after encryption. Nonce reuse would be
        catastrophic for security, so we check for overflow even though
        reaching 2^64 messages is practically impossible.
        """
        # Check BEFORE encryption to never use invalid nonce.
        if self.nonce >= MAX_NONCE:
            raise CipherError("Nonce overflow - connection must be rekeyed or closed")

        ciphertext = encrypt(self.key, self.nonce, ad, plaintext)

        # Increment after success. Failure allows retry with same nonce.
        self.nonce += 1
        return ciphertext

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext with associated data.

        Args:
            ad: Associated data (must match encryption).
            ciphertext: Encrypted data with auth tag.

        Returns:
            Decrypted plaintext.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails.
            CipherError: If nonce would overflow (2^64 messages received).

        The nonce auto-increments after decryption. We check for overflow
        to ensure the same nonce is never used twice.
        """
        # Symmetric with encrypt: check before, increment after.
        if self.nonce >= MAX_NONCE:
            raise CipherError("Nonce overflow - connection must be rekeyed or closed")

        plaintext = decrypt(self.key, self.nonce, ad, ciphertext)

        # Increment only on success. Failure preserves nonce for retry.
        self.nonce += 1
        return plaintext

    def has_key(self) -> bool:
        """Check if cipher state has been initialized with a key."""
        return self.key is not None and len(self.key) == 32


@dataclass(slots=True)
class SymmetricState:
    """
    Symmetric cryptographic state during handshake.

    Tracks:
        - Chaining key (ck): Evolves with each DH operation
        - Handshake hash (h): Accumulates transcript for binding
        - Current cipher state: For encrypting handshake payloads

    The chaining key provides forward secrecy by mixing in new DH
    outputs. The handshake hash binds all exchanged data together,
    preventing transcript manipulation.
    """

    # Both start with hash(protocol_name).
    # Binds handshake to specific Noise variant (XX, X25519, ChaCha20-Poly1305).
    # Different protocol names -> different keys -> prevents cross-protocol confusion.
    chaining_key: ChainingKey = field(default_factory=lambda: ChainingKey(PROTOCOL_NAME_HASH))
    """32-byte chaining key, initialized to hash of protocol name."""

    handshake_hash: HandshakeHash = field(default_factory=lambda: HandshakeHash(PROTOCOL_NAME_HASH))
    """32-byte hash accumulating the handshake transcript."""

    cipher_state: CipherState | None = None
    """Cipher for encrypted handshake payloads (None until first DH)."""

    def mix_key(self, input_key_material: SharedSecret) -> None:
        """
        Mix new key material into the chaining key.

        Called after each DH operation to evolve the state.
        Derives a new chaining key and optionally a cipher key.

        Args:
            input_key_material: DH output (32-byte shared secret)

        This is the core of Noise's forward secrecy: each DH output
        is mixed in, so compromising later keys doesn't reveal
        earlier session keys.
        """
        # HKDF produces two outputs:
        # - new_chaining_key: accumulates all DH secrets (forward secrecy)
        # - temp_key: encryption key for next handshake payload
        #
        # chaining_key never leaves this object.
        # Even if attacker steals temp_key, cannot derive past/future keys.
        new_chaining_key, temp_key = hkdf_sha256(self.chaining_key, input_key_material)
        self.chaining_key = ChainingKey(new_chaining_key)

        # Fresh cipher with nonce=0.
        # Each DH produces new cipher. No nonce exhaustion risk in handshake.
        self.cipher_state = CipherState(key=CipherKey(temp_key))

    def mix_hash(self, data: bytes) -> None:
        """
        Mix data into the handshake hash.

        Called to bind public keys and ciphertexts to the transcript.

        Args:
            data: Data to mix in (e.g., public key bytes)

        The handshake hash becomes associated data for encrypted
        payloads, binding the entire transcript together.
        """
        # hash(prev_hash || new_data) creates commitment to full transcript.
        #
        # Security properties:
        # - Neither party can claim different data was exchanged
        # - Used as AD for encryption -> tampering causes InvalidTag
        # - Prevents "splicing" parts of different handshakes
        self.handshake_hash = HandshakeHash(sha256(bytes(self.handshake_hash) + data))

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """
        Encrypt payload and mix ciphertext into hash.

        Used to encrypt static keys during handshake.

        Args:
            plaintext: Data to encrypt (e.g., static public key)

        Returns:
            Ciphertext (to send over wire)
        """
        if self.cipher_state is None:
            # Before first DH: no encryption key yet.
            # In XX pattern, message 1 is sent unencrypted.
            # Still bind to hash for transcript consistency.
            self.mix_hash(plaintext)
            return plaintext

        # Encrypt with handshake_hash as AD.
        # Binds ciphertext to all previous messages.
        #
        # Attacker cannot:
        # - Replay in different handshake (wrong transcript)
        # - Modify prior messages (hash changes -> auth fails)
        ciphertext = self.cipher_state.encrypt_with_ad(self.handshake_hash, plaintext)

        # Mix CIPHERTEXT (not plaintext).
        # Both parties mix same bytes -> synchronized transcripts.
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        """
        Decrypt payload and mix ciphertext into hash.

        Used to decrypt peer's static key during handshake.

        Args:
            ciphertext: Encrypted data from peer

        Returns:
            Decrypted plaintext

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        if self.cipher_state is None:
            # Before first DH: data is plaintext.
            # Still bind to hash for transcript consistency.
            self.mix_hash(ciphertext)
            return ciphertext

        # Decrypt with handshake_hash as AD.
        #
        # InvalidTag failure means:
        # - Ciphertext tampered, OR
        # - Transcripts diverged (protocol bug)
        # Either way: terminate handshake immediately.
        plaintext = self.cipher_state.decrypt_with_ad(self.handshake_hash, ciphertext)

        # Mix CIPHERTEXT (same as sender did).
        # Keeps transcripts synchronized.
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> tuple[CipherState, CipherState]:
        """
        Derive final cipher states for transport.

        Called after handshake completes to derive send/receive keys.

        Returns:
            (send_cipher, recv_cipher) for initiator
            (recv_cipher, send_cipher) for responder

        The initiator uses cipher1 for sending, cipher2 for receiving.
        The responder uses cipher2 for sending, cipher1 for receiving.
        """
        # Empty input_key_material signals "no more DH operations".
        #
        # Derive two transport keys from chaining_key.
        # chaining_key contains entropy from all three DH operations (ee, es, se).
        #
        # Why two keys?
        # - Each direction needs own key + nonce counter
        # - Prevents reflection attacks: can't echo message back as valid
        temp_key1, temp_key2 = hkdf_sha256(self.chaining_key, b"")

        # Fresh ciphers with nonce=0 for transport phase.
        # These encrypt all subsequent application data.
        return (
            CipherState(key=CipherKey(temp_key1)),
            CipherState(key=CipherKey(temp_key2)),
        )


@dataclass(slots=True)
class HandshakePattern:
    """
    Descriptor for a Noise handshake pattern.

    Noise patterns define the sequence of DH operations and
    key exchanges. The XX pattern is:
        -> e       (initiator ephemeral)
        <- e, ee, s, es (responder ephemeral, DH, static, DH)
        -> s, se   (initiator static, DH)

    Legend:
        e = ephemeral public key
        s = static public key
        ee = DH(ephemeral, ephemeral)
        es = DH(ephemeral, static)
        se = DH(static, ephemeral)
    """

    name: str
    """Pattern name (e.g., 'XX')."""

    initiator_pre_messages: tuple[str, ...] = ()
    """Pre-message keys for initiator (empty for XX)."""

    responder_pre_messages: tuple[str, ...] = ()
    """Pre-message keys for responder (empty for XX)."""

    message_patterns: tuple[tuple[str, ...], ...] = ()
    """Sequence of message patterns."""


XX_PATTERN = HandshakePattern(
    name="XX",
    initiator_pre_messages=(),
    responder_pre_messages=(),
    message_patterns=(
        ("e",),  # Message 1: Initiator sends ephemeral
        ("e", "ee", "s", "es"),  # Message 2: Responder full
        ("s", "se"),  # Message 3: Initiator static
    ),
)
"""The XX handshake pattern used by libp2p."""
