"""
This package provides a Python specification for the Generalized XMSS
hash-based signature scheme.

It exposes the core data structures and the main interface functions.
"""

from .constants import LEAN_ENV, PROD_CONFIG, TARGET_CONFIG, TEST_CONFIG
from .containers import PublicKey, SecretKey, Signature
from .interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme
from .types import HashTreeOpening

__all__ = [
    "GeneralizedXmssScheme",
    "PublicKey",
    "Signature",
    "SecretKey",
    "HashTreeOpening",
    "PROD_CONFIG",
    "TEST_CONFIG",
    "LEAN_ENV",
    "TARGET_CONFIG",
    "TARGET_SIGNATURE_SCHEME",
]
