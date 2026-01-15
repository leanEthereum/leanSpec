"""
Cryptographic primitives for Noise protocol.

libp2p-noise uses:
    - X25519 for Diffie-Hellman key agreement (NOT secp256k1)
    - ChaCha20-Poly1305 for authenticated encryption
    - SHA256 for hashing and key derivation

secp256k1 is used ONLY for libp2p identity (PeerId derivation),
not for the Noise handshake itself. The Noise protocol uses X25519
for ephemeral key exchange because it's faster and provides better
forward secrecy properties.

Wire format notes:
    - ChaCha20-Poly1305 nonce: 12 bytes, first 4 are zeros, last 8 are LE counter
    - Ciphertext includes 16-byte authentication tag appended
    - HKDF uses SHA256 with empty salt, outputs two 32-byte keys

References:
    - https://noiseprotocol.org/noise.html#the-cipherstate-object
    - https://datatracker.ietf.org/doc/html/rfc7748 (X25519)
    - https://datatracker.ietf.org/doc/html/rfc8439 (ChaCha20-Poly1305)
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from lean_spec.types import Bytes32


def x25519_dh(private_key: x25519.X25519PrivateKey, public_key: x25519.X25519PublicKey) -> Bytes32:
    """
    Perform X25519 Diffie-Hellman key exchange.

    X25519 is the Elliptic Curve Diffie-Hellman function using Curve25519.
    Both parties compute the same shared secret from their private key
    and the other party's public key.

    Args:
        private_key: Our X25519 private key
        public_key: Peer's X25519 public key

    Returns:
        32-byte shared secret
    """
    return Bytes32(private_key.exchange(public_key))


def encrypt(key: Bytes32, nonce: int, ad: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt with ChaCha20-Poly1305 AEAD.

    The nonce is an 8-byte counter (little-endian) padded with 4 leading zeros
    to form the 12-byte nonce required by ChaCha20-Poly1305.

    Args:
        key: 32-byte encryption key
        nonce: 64-bit counter value (will be converted to 12-byte nonce)
        ad: Associated data (authenticated but not encrypted)
        plaintext: Data to encrypt

    Returns:
        Ciphertext with 16-byte authentication tag appended

    Nonce format:
        [0x00, 0x00, 0x00, 0x00] + [nonce as 8-byte little-endian]

    The 4-byte zero prefix is per the Noise spec. The counter starts at 0
    and increments for each message. Nonce reuse would be catastrophic
    for security, so the counter must never wrap or repeat.
    """
    # Build 12-byte nonce: 4 zeros + 8-byte LE counter
    nonce_bytes = b"\x00\x00\x00\x00" + struct.pack("<Q", nonce)

    cipher = ChaCha20Poly1305(bytes(key))
    return cipher.encrypt(nonce_bytes, plaintext, ad)


def decrypt(key: Bytes32, nonce: int, ad: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt with ChaCha20-Poly1305 AEAD.

    Verifies the authentication tag and decrypts if valid.

    Args:
        key: 32-byte encryption key
        nonce: 64-bit counter value (must match encryption nonce)
        ad: Associated data (must match encryption AD)
        ciphertext: Ciphertext with 16-byte auth tag

    Returns:
        Decrypted plaintext

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails

    Authentication failure indicates either:
        1. Tampered ciphertext
        2. Wrong key
        3. Wrong nonce
        4. Wrong associated data
    All are treated identically to prevent oracle attacks.
    """
    nonce_bytes = b"\x00\x00\x00\x00" + struct.pack("<Q", nonce)

    cipher = ChaCha20Poly1305(bytes(key))
    return cipher.decrypt(nonce_bytes, ciphertext, ad)


def hkdf_sha256(chaining_key: Bytes32, input_key_material: bytes) -> tuple[Bytes32, Bytes32]:
    """
    Derive two 32-byte keys using HKDF per the Noise protocol specification.

    This implements the Noise-specific HKDF defined in section 4 of the spec:
        temp_key = HMAC-HASH(chaining_key, input_key_material)
        output1 = HMAC-HASH(temp_key, byte(0x01))
        output2 = HMAC-HASH(temp_key, output1 || byte(0x02))

    Args:
        chaining_key: 32-byte chaining key from previous operation.
        input_key_material: New key material (e.g., DH output).

    Returns:
        Tuple of (new_chaining_key, output_key), each 32 bytes.

    Why use explicit HMAC instead of RFC 5869 HKDF?

    While RFC 5869 HKDF with empty info produces equivalent results,
    implementing the Noise spec's HMAC-based definition explicitly:
        1. Makes the code directly auditable against the spec
        2. Removes any ambiguity about parameter ordering
        3. Ensures interoperability with other implementations

    The Noise protocol uses this function to:
        1. Mix new DH outputs into the chaining key (forward secrecy)
        2. Derive encryption keys from the chaining key
        3. Split the final state into send/receive cipher keys
    """
    # Extract phase: HMAC(chaining_key, input_key_material) -> temp_key.
    #
    # chaining_key as MAC key is critical:
    # - Weak ikm cannot predict output without knowing chaining_key
    # - chaining_key acts as "secret accumulator" binding all DH outputs
    temp_key = hmac.new(bytes(chaining_key), input_key_material, hashlib.sha256).digest()

    # Expand phase: derive two keys with counter bytes.
    #
    # Counter (0x01, 0x02) ensures cryptographic independence.
    # output1 -> new chaining key (carries forward secrecy)
    output1 = hmac.new(temp_key, b"\x01", hashlib.sha256).digest()

    # output2 -> encryption key (used immediately).
    #
    # Include output1 in input creates dependency chain:
    # Cannot compute output2 without computing output1.
    # Prevents selective key derivation.
    output2 = hmac.new(temp_key, output1 + b"\x02", hashlib.sha256).digest()

    return Bytes32(output1), Bytes32(output2)


def sha256(data: bytes) -> Bytes32:
    """
    Compute SHA256 hash.

    Used for:
        - Hashing the protocol name
        - Mixing public keys into the handshake hash

    Args:
        data: Data to hash

    Returns:
        32-byte hash digest
    """
    return Bytes32(hashlib.sha256(data).digest())


def generate_keypair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """
    Generate a new X25519 keypair.

    Used to create ephemeral keys for each handshake.
    Each connection uses fresh ephemeral keys for forward secrecy.

    Returns:
        Tuple of (private_key, public_key)
        - private_key: X25519PrivateKey object for DH operations
        - public_key: X25519PublicKey object for key exchange
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key
