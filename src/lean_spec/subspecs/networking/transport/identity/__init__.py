"""
libp2p identity module.

Provides secp256k1 keypair management for peer identity (PeerId derivation).
"""

from .keypair import IdentityKeypair, Secp256k1PublicKey

__all__ = [
    "IdentityKeypair",
    "Secp256k1PublicKey",
]
