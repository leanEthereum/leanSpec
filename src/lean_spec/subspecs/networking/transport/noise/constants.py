"""
Constants and type aliases for Noise protocol.

This module contains:
    - Protocol constants (name, hash)
    - Domain-specific type aliases for cryptographic values

Separated to avoid circular imports between crypto.py and types.py.
"""

from __future__ import annotations

import hashlib
from typing import Final, TypeAlias

from lean_spec.types import Bytes32

# =============================================================================
# Protocol Constants
# =============================================================================

PROTOCOL_NAME: Final[bytes] = b"Noise_XX_25519_ChaChaPoly_SHA256"
"""Noise protocol name per the Noise spec. Used to initialize the handshake state."""

PROTOCOL_NAME_HASH: Final[Bytes32] = Bytes32(hashlib.sha256(PROTOCOL_NAME).digest())
"""SHA256 hash of protocol name. Used as initial chaining key and hash value."""

# Nonce overflow protection (Noise spec section 5.1).
# Reusing a nonce breaks confidentiality: C1 XOR C2 = P1 XOR P2.
# 2^64 is unreachable, but we check anyway for defense in depth.
MAX_NONCE: Final[int] = (1 << 64) - 1
"""Maximum nonce value before overflow (2^64 - 1)."""

# =============================================================================
# Domain-Specific Type Aliases
# =============================================================================
#
# These aliases provide semantic clarity for cryptographic values.
# All are 32 bytes, but each serves a distinct purpose in the protocol.
#
# Note: For X25519 public/private keys, use the cryptography library types
# directly (x25519.X25519PublicKey, x25519.X25519PrivateKey) rather than
# byte aliases. The aliases below are for derived values like shared secrets.

SharedSecret: TypeAlias = Bytes32
"""32-byte X25519 Diffie-Hellman shared secret."""

CipherKey: TypeAlias = Bytes32
"""32-byte ChaCha20-Poly1305 encryption key."""

ChainingKey: TypeAlias = Bytes32
"""32-byte HKDF chaining key for forward secrecy."""

HandshakeHash: TypeAlias = Bytes32
"""32-byte SHA256 hash binding the handshake transcript."""
