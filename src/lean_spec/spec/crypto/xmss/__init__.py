"""Generalized XMSS hash-based signature scheme.

References:
    - Hash-Based Multi-Signatures for Post-Quantum Ethereum.
      https://eprint.iacr.org/2025/055.pdf
    - Aborting Random Oracles, How to Build Them, How to Use Them.
      https://eprint.iacr.org/2026/016.pdf
"""

from .containers import PublicKey, SecretKey
from .interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme

__all__ = [
    "GeneralizedXmssScheme",
    "PublicKey",
    "SecretKey",
    "TARGET_SIGNATURE_SCHEME",
]
