"""
This package provides a Python specification for the Generalized XMSS
hash-based signature scheme.

It exposes the core data structures and the main interface functions.
"""

from .constants import ENV_CONFIG, LEAN_ENV, PROD_CONFIG, TEST_CONFIG
from .containers import PublicKey, SecretKey, Signature
from .interface import XMSS_SIGNATURE_SCHEME, GeneralizedXmssScheme
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
    "ENV_CONFIG",
    "XMSS_SIGNATURE_SCHEME",
]
