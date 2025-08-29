"""
This package provides a Python specification for the Generalized XMSS
hash-based signature scheme.

It exposes the core data structures and the main interface functions.
"""

from .constants import LIFETIME, MESSAGE_LENGTH
from .interface import key_gen, sign, verify
from .merkle_tree import build_tree, get_path, get_root, verify_path
from .structures import (
    HashTree,
    HashTreeOpening,
    PublicKey,
    SecretKey,
    Signature,
)

__all__ = [
    "key_gen",
    "sign",
    "verify",
    "PublicKey",
    "Signature",
    "SecretKey",
    "HashTreeOpening",
    "LIFETIME",
    "MESSAGE_LENGTH",
    "build_tree",
    "get_path",
    "get_root",
    "verify_path",
    "HashTree",
]
