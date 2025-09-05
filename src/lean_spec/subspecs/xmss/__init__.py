"""
This package provides a Python specification for the Generalized XMSS
hash-based signature scheme.

It exposes the core data structures and the main interface functions.
"""

from .constants import PROD_CONFIG, TEST_CONFIG
from .containers import (
    HashTree,
    HashTreeOpening,
    PublicKey,
    SecretKey,
    Signature,
)
from .interface import GeneralizedXmssScheme

__all__ = [
    "GeneralizedXmssScheme",
    "PublicKey",
    "Signature",
    "SecretKey",
    "HashTreeOpening",
    "HashTree",
    "PROD_CONFIG",
    "TEST_CONFIG",
]
