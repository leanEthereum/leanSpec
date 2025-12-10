"""
This package provides a Python specification for the Generalized XMSS
hash-based signature scheme.

It exposes the core data structures and the main interface functions.
"""

from .constants import LEAN_ENV, PROD_CONFIG, TEST_CONFIG, ENV_CONFIG
from .containers import PublicKey, SecretKey, Signature
from .interface import GeneralizedXmssScheme, XMSS_SIGNATURE_SCHEME
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
