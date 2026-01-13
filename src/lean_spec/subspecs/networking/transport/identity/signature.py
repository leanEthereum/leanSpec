"""
Identity proof for libp2p-noise handshake.

During the Noise handshake, peers must prove they own their claimed
libp2p identity key by signing the Noise static public key.

The signature format follows the libp2p-noise specification:
    message = "noise-libp2p-static-key:" || noise_public_key
    signature = ECDSA-SHA256(identity_private_key, message)

References:
    - https://github.com/libp2p/specs/blob/master/noise/README.md
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from .keypair import verify_signature

if TYPE_CHECKING:
    from .keypair import IdentityKeypair

__all__ = [
    "NOISE_IDENTITY_PREFIX",
    "create_identity_proof",
    "verify_identity_proof",
]


NOISE_IDENTITY_PREFIX: Final[bytes] = b"noise-libp2p-static-key:"
"""Prefix for the identity proof message per libp2p-noise spec."""


def create_identity_proof(
    identity_key: IdentityKeypair,
    noise_public_key: bytes,
) -> bytes:
    """
    Create identity proof signature for Noise handshake.

    Proves that the owner of the identity key (secp256k1) also controls
    the Noise static key (X25519). This binding prevents man-in-the-middle
    attacks where an attacker substitutes their Noise key.

    Args:
        identity_key: The secp256k1 identity keypair.
        noise_public_key: The 32-byte X25519 Noise static public key.

    Returns:
        DER-encoded ECDSA signature.
    """
    message = NOISE_IDENTITY_PREFIX + noise_public_key
    return identity_key.sign(message)


def verify_identity_proof(
    identity_public_key: bytes,
    noise_public_key: bytes,
    signature: bytes,
) -> bool:
    """
    Verify identity proof signature.

    Called during Noise handshake to verify the remote peer's identity claim.

    Args:
        identity_public_key: 33-byte compressed secp256k1 public key.
        noise_public_key: 32-byte X25519 Noise static public key.
        signature: DER-encoded ECDSA signature.

    Returns:
        True if the signature is valid, False otherwise.
    """
    message = NOISE_IDENTITY_PREFIX + noise_public_key
    return verify_signature(identity_public_key, message, signature)
