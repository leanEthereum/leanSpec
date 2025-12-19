"""
Data containers for the Generalized XMSS signature scheme.

This module defines the high-level containers: PublicKey, Signature, and SecretKey.
Base types (HashDigestVector, Parameter, etc.) are defined in types.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...types import Uint64
from ...types.container import Container
from .subtree import HashSubTree
from .types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
    PRFKey,
    Randomness,
)

if TYPE_CHECKING:
    from .interface import GeneralizedXmssScheme


class PublicKey(Container):
    """
    The public-facing component of a key pair.

    This is the data a verifier needs to check signatures. It is compact, safe to
    distribute publicly, and acts as the signer's identity.

    SSZ Container with fields:
    - root: Vector[Fp, HASH_LEN_FE]
    - parameter: Vector[Fp, PARAMETER_LEN]

    Serialization is handled automatically by SSZ.
    """

    root: HashDigestVector
    """The Merkle root, which commits to all one-time keys for the key's lifetime."""
    parameter: Parameter
    """The public parameter `P` that personalizes the hash function."""


class Signature(Container):
    """
    A signature produced by the `sign` function.

    It contains all the necessary components for a verifier to confirm that a
    specific message was signed by the owner of a `PublicKey` for a specific epoch.

    SSZ Container with fields:
    - path: HashTreeOpening (container with siblings list)
    - rho: Vector[Fp, RAND_LEN_FE]
    - hashes: List[Vector[Fp, HASH_DIGEST_LENGTH], NODE_LIST_LIMIT]

    Serialization is handled automatically by SSZ.
    """

    path: HashTreeOpening
    """The authentication path proving the one-time key's inclusion in the Merkle tree."""
    rho: Randomness
    """The randomness used to successfully encode the message."""
    hashes: HashDigestList
    """The one-time signature itself: a list of intermediate Winternitz chain hashes."""

    def verify(
        self,
        public_key: PublicKey,
        epoch: "Uint64",
        message: bytes,
        scheme: "GeneralizedXmssScheme",
    ) -> bool:
        """
        Verify the signature using XMSS verification algorithm.

        This is a convenience method that delegates to `scheme.verify()`.

        Invalid or malformed signatures return `False`.

        Expected exceptions:
        - `ValueError` for invalid epochs,
        - `IndexError` for malformed signatures
        are caught and converted to `False`.

        Args:
            public_key: The public key to verify against.
            epoch: The epoch the signature corresponds to.
            message: The message that was supposedly signed.
            scheme: The XMSS scheme instance to use for verification.

        Returns:
            `True` if the signature is valid, `False` otherwise.
        """
        try:
            return scheme.verify(public_key, epoch, message, self)
        except (ValueError, IndexError):
            return False


class SecretKey(Container):
    """
    The private component of a key pair. **MUST BE KEPT CONFIDENTIAL.**

    This object contains all the secret material and pre-computed data needed to
    generate signatures for any epoch within its active lifetime.

    SSZ Container with fields:
    - prf_key: Bytes[PRF_KEY_LENGTH]
    - parameter: Vector[Fp, PARAMETER_LEN]
    - activation_epoch: uint64
    - num_active_epochs: uint64
    - top_tree: HashSubTree
    - left_bottom_tree_index: uint64
    - left_bottom_tree: HashSubTree
    - right_bottom_tree: HashSubTree

    Serialization is handled automatically by SSZ.
    """

    prf_key: PRFKey
    """The master secret key used to derive all one-time secrets."""

    parameter: Parameter
    """The public parameter `P`, stored for convenience during signing."""

    activation_epoch: Uint64
    """
    The first epoch for which this secret key is valid.

    Note: With top-bottom trees, this is aligned to a multiple of `sqrt(LIFETIME)`
    to ensure efficient tree partitioning.
    """

    num_active_epochs: Uint64
    """
    The number of consecutive epochs this key can be used for.

    Note: With top-bottom trees, this is rounded up to be a multiple of
    `sqrt(LIFETIME)`, with a minimum of `2 * sqrt(LIFETIME)`.
    """

    top_tree: HashSubTree
    """
    The top tree containing the root and top `LOG_LIFETIME/2` layers.

    This tree is always kept in memory and contains the roots of all bottom trees
    in its lowest layer. Its root is the public key's Merkle root.
    """

    left_bottom_tree_index: Uint64
    """
    The index of the left bottom tree in the sliding window.

    Bottom trees are numbered 0, 1, 2, ... where tree `i` covers epochs
    `[i * sqrt(LIFETIME), (i+1) * sqrt(LIFETIME))`.

    The prepared interval is:
    [left_bottom_tree_index * sqrt(LIFETIME), (left_bottom_tree_index + 2) * sqrt(LIFETIME))

    """

    left_bottom_tree: HashSubTree
    """
    The left bottom tree in the sliding window.

    This covers epochs:
    [left_bottom_tree_index * sqrt(LIFETIME), (left_bottom_tree_index + 1) * sqrt(LIFETIME))
    """

    right_bottom_tree: HashSubTree
    """
    The right bottom tree in the sliding window.

    This covers epochs:
    [(left_bottom_tree_index + 1) * sqrt(LIFETIME), (left_bottom_tree_index + 2) * sqrt(LIFETIME))

    Together with `left_bottom_tree`, this provides a prepared interval of
    exactly `2 * sqrt(LIFETIME)` consecutive epochs.
    """
