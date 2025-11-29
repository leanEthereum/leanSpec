"""Defines the data containers for the Generalized XMSS signature scheme."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lean_spec.subspecs.koalabear import Fp

from ...types import Uint64
from ...types.byte_arrays import BaseBytes
from ...types.collections import SSZList, SSZVector
from ...types.container import Container
from .constants import PRF_KEY_LENGTH, PROD_CONFIG

if TYPE_CHECKING:
    from .interface import GeneralizedXmssScheme
    from .subtree import HashSubTree


class PRFKey(BaseBytes):
    """
    The PRF master secret key.

    This is a high-entropy byte string that acts as the single root secret from
    which all one-time signing keys are deterministically derived.
    """

    LENGTH = PRF_KEY_LENGTH


HASH_DIGEST_LENGTH = PROD_CONFIG.HASH_LEN_FE
"""
The fixed length of a hash digest in field elements.

Derived from `PROD_CONFIG.HASH_LEN_FE`. This corresponds to the output length
of the Poseidon2 hash function used in the XMSS scheme.
"""

# Calculate the maximum number of nodes in a sparse Merkle tree layer:
# - A bottom tree has at most 2^(LOG_LIFETIME/2) leaves
# - With padding, we may add up to 2 additional nodes
# - To be generous and future-proof, we use 2^(LOG_LIFETIME/2 + 1)
NODE_LIST_LIMIT = 1 << (PROD_CONFIG.LOG_LIFETIME // 2 + 1)
"""
The maximum number of nodes that can be stored in a sparse Merkle tree layer.

Calculated as `2^(LOG_LIFETIME/2 + 1)` from PROD_CONFIG to accommodate:
- Bottom trees with up to `2^(LOG_LIFETIME/2)` nodes
- Padding overhead (up to 2 additional nodes)
- Future-proofing with 2x margin
"""


class HashDigestVector(SSZVector):
    """
    A single hash digest represented as a fixed-size vector of field elements.

    This is the SSZ-compliant representation of a Poseidon2 hash output.
    In SSZ notation: `Vector[Fp, HASH_DIGEST_LENGTH]`

    The fixed size enables efficient serialization when used in collections,
    as SSZ can pack these back-to-back without per-element offsets.
    """

    ELEMENT_TYPE = Fp
    LENGTH = HASH_DIGEST_LENGTH


class HashDigestList(SSZList):
    """
    Variable-length list of hash digests.

    In SSZ notation: `List[Vector[Fp, HASH_DIGEST_LENGTH], NODE_LIST_LIMIT]`

    This type is used to represent collections of hash digests in the XMSS scheme.
    """

    ELEMENT_TYPE = HashDigestVector
    LIMIT = NODE_LIST_LIMIT


class Parameter(SSZVector):
    """
    The public parameter P.

    This is a unique, randomly generated value associated with a single key pair. It
    is mixed into every hash computation to "personalize" the hash function, preventing
    certain cross-key attacks. It is public knowledge.
    """

    ELEMENT_TYPE = Fp
    LENGTH = PROD_CONFIG.PARAMETER_LEN


class Randomness(SSZVector):
    """
    The randomness `rho` (ρ) used during signing.

    This value provides a variable input to the message hash, allowing the signer to
    repeatedly try hashing until a valid "codeword" is found. It must be included in
    the final signature for the verifier to reproduce the same hash.

    SSZ notation: `Vector[Fp, RAND_LEN_FE]`
    """

    ELEMENT_TYPE = Fp
    LENGTH = PROD_CONFIG.RAND_LEN_FE


class HashTreeOpening(Container):
    """
    A Merkle authentication path.

    This object contains the minimal proof required to connect a specific leaf
    to the Merkle root. It consists of the list of all sibling nodes along the
    path from the leaf to the top of the tree.

    SSZ Container with fields:
    - siblings: List[Vector[Fp, HASH_DIGEST_LENGTH], NODE_LIST_LIMIT]
    """

    siblings: HashDigestList
    """SSZ-compliant list of sibling hashes, from bottom to top."""


class HashTreeLayer(Container):
    """
    Represents a single horizontal "slice" of the sparse Merkle tree.

    Because the tree is sparse, we only store the nodes that are actually computed
    for the active range of leaves, not the entire conceptual layer.
    """

    start_index: Uint64
    """The starting index of the first node in this layer."""
    nodes: HashDigestList
    """SSZ-compliant list of hash digests stored for this layer."""


LAYERS_LIMIT = PROD_CONFIG.LOG_LIFETIME + 1
"""
The maximum number of layers in a subtree.

This is `LOG_LIFETIME + 1` to accommodate all layers from 0 (leaves) to LOG_LIFETIME (root),
inclusive. For PROD_CONFIG with LOG_LIFETIME=32, this allows up to 33 layers.
"""


class HashTreeLayers(SSZList):
    """
    Variable-length list of Merkle tree layers.

    In SSZ notation: `List[HashTreeLayer, LAYERS_LIMIT]`

    This type represents the layers of a subtree, from the lowest layer up to the root.

    The number of layers varies based on the subtree structure:
    - Bottom trees: `LOG_LIFETIME/2` layers
    - Top trees: `LOG_LIFETIME/2` layers
    - Maximum: `LOG_LIFETIME + 1` layers
    """

    ELEMENT_TYPE = HashTreeLayer
    LIMIT = LAYERS_LIMIT


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
        scheme: "GeneralizedXmssScheme | None" = None,
    ) -> bool:
        """Verify the signature using XMSS verification algorithm."""
        from .interface import TEST_SIGNATURE_SCHEME

        if scheme is None:
            scheme = TEST_SIGNATURE_SCHEME

        try:
            return scheme.verify(public_key, epoch, message, self)
        except Exception:
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

    top_tree: "HashSubTree"
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

    left_bottom_tree: "HashSubTree"
    """
    The left bottom tree in the sliding window.

    This covers epochs:
    [left_bottom_tree_index * sqrt(LIFETIME), (left_bottom_tree_index + 1) * sqrt(LIFETIME))
    """

    right_bottom_tree: "HashSubTree"
    """
    The right bottom tree in the sliding window.

    This covers epochs:
    [(left_bottom_tree_index + 1) * sqrt(LIFETIME), (left_bottom_tree_index + 2) * sqrt(LIFETIME))

    Together with `left_bottom_tree`, this provides a prepared interval of
    exactly `2 * sqrt(LIFETIME)` consecutive epochs.
    """
