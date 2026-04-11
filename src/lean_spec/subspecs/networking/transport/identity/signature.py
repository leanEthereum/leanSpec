"""
Identity proof for libp2p peer authentication.

During the QUIC TLS handshake, peers must prove they own their claimed
libp2p identity key by signing the TLS public key.

The signature format follows the libp2p specification:
    message = "noise-libp2p-static-key:" || public_key
    signature = ECDSA-SHA256(identity_private_key, message)

References:
    - https://github.com/libp2p/specs/blob/master/noise/README.md
"""

from __future__ import annotations

from typing import Final

from lean_spec.types import Bytes32

from .keypair import IdentityKeypair, Secp256k1PublicKey

__all__ = [
    "NOISE_IDENTITY_PREFIX",
    "create_identity_proof",
    "verify_identity_proof",
]


NOISE_IDENTITY_PREFIX: Final[bytes] = b"noise-libp2p-static-key:"
"""Prefix for the identity proof message per libp2p-noise spec."""


def create_identity_proof(
    identity_key: IdentityKeypair,
    public_key: Bytes32,
) -> bytes:
    """
    Create identity proof signature for peer authentication.

    Proves that the owner of the identity key (secp256k1) also controls
    the TLS static key. This binding prevents man-in-the-middle attacks.

    Args:
        identity_key: The secp256k1 identity keypair.
        public_key: The 32-byte TLS public key.

    Returns:
        DER-encoded ECDSA signature.
    """
    message = NOISE_IDENTITY_PREFIX + public_key
    return identity_key.sign(message)


def verify_identity_proof(
    identity_public_key: Secp256k1PublicKey,
    public_key: Bytes32,
    signature: bytes,
) -> bool:
    """
    Verify identity proof signature.

    Called during QUIC TLS handshake to verify the remote peer's identity claim.

    Args:
        identity_public_key: The secp256k1 public key claiming identity.
        public_key: 32-byte TLS public key.
        signature: DER-encoded ECDSA signature.

    Returns:
        True if the signature is valid, False otherwise.
    """
    message = NOISE_IDENTITY_PREFIX + public_key
    return identity_public_key.verify(message, signature)
