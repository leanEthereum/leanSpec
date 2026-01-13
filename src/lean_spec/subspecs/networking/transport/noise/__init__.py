"""
Noise protocol implementation for libp2p.

libp2p uses Noise_XX_25519_ChaChaPoly_SHA256:
    - XX pattern: mutual authentication, forward secrecy
    - X25519: Diffie-Hellman key exchange
    - ChaCha20-Poly1305: authenticated encryption
    - SHA256: hashing and key derivation

The XX pattern has three messages:
    -> e                 # Initiator sends ephemeral pubkey
    <- e, ee, s, es      # Responder: ephemeral, DH, static (encrypted), DH
    -> s, se             # Initiator: static (encrypted), DH

After handshake:
    - Both parties know each other's static pubkey (libp2p identity)
    - Forward secrecy: past sessions protected if static keys compromised
    - Two cipher states: one for each direction

References:
    - https://noiseprotocol.org/noise.html
    - https://github.com/libp2p/specs/tree/master/noise
"""

from .constants import (
    PROTOCOL_NAME,
    PROTOCOL_NAME_HASH,
    ChainingKey,
    CipherKey,
    HandshakeHash,
    SharedSecret,
)
from .crypto import decrypt, encrypt, hkdf_sha256, x25519_dh
from .handshake import NoiseHandshake
from .payload import NoiseIdentityPayload
from .session import NoiseSession
from .types import CipherState

__all__ = [
    # Constants
    "PROTOCOL_NAME",
    "PROTOCOL_NAME_HASH",
    # Type aliases (for internal state, use cryptography types for keys)
    "ChainingKey",
    "CipherKey",
    "HandshakeHash",
    "SharedSecret",
    # Primitives
    "x25519_dh",
    "encrypt",
    "decrypt",
    "hkdf_sha256",
    # Classes
    "NoiseHandshake",
    "NoiseSession",
    "NoiseIdentityPayload",
    "CipherState",
]
