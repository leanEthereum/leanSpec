"""
libp2p identity module.

Provides secp256k1 keypair management for peer identity and identity
proof signatures for the Noise handshake.

The identity key is separate from the Noise key:
- Identity key (secp256k1): Used to derive PeerId, sign identity proofs
- Noise key (X25519): Used for encrypted communication

This separation follows the libp2p-noise specification and matches
the approach used by ream and zeam.
"""

from .keypair import IdentityKeypair, verify_signature
from .signature import (
    NOISE_IDENTITY_PREFIX,
    create_identity_proof,
    verify_identity_proof,
)

__all__ = [
    "IdentityKeypair",
    "verify_signature",
    "NOISE_IDENTITY_PREFIX",
    "create_identity_proof",
    "verify_identity_proof",
]
