"""Base types for the XMSS signature scheme."""

from typing import List

from lean_spec.subspecs.koalabear import Fp

from ...types import Uint64
from ...types.byte_arrays import BaseBytes
from ...types.collections import SSZList, SSZVector
from ...types.container import Container
from .constants import TARGET_CONFIG, PRF_KEY_LENGTH


class PRFKey(BaseBytes):
    """
    The PRF master secret key.

    This is a high-entropy byte string that acts as the single root secret from
    which all one-time signing keys are deterministically derived.
    """

    LENGTH = PRF_KEY_LENGTH


HASH_DIGEST_LENGTH = TARGET_CONFIG.HASH_LEN_FE
"""
The fixed length of a hash digest in field elements.

Derived from `TARGET_CONFIG.HASH_LEN_FE`. This corresponds to the output length
of the Poseidon2 hash function used in the XMSS scheme.
"""

# Calculate the maximum number of nodes in a sparse Merkle tree layer:
# - A bottom tree has at most 2^(LOG_LIFETIME/2) leaves
# - With padding, we may add up to 2 additional nodes
# - To be generous and future-proof, we use 2^(LOG_LIFETIME/2 + 1)
NODE_LIST_LIMIT = 1 << (TARGET_CONFIG.LOG_LIFETIME // 2 + 1)
"""
The maximum number of nodes that can be stored in a sparse Merkle tree layer.

Calculated as `2^(LOG_LIFETIME/2 + 1)` from TARGET_CONFIG to accommodate:
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

    @property
    def elements(self) -> List[Fp]:
        """Return the field elements as a typed list."""
        return list(self.data)  # type: ignore[arg-type]


class HashDigestList(SSZList):
    """
    Variable-length list of hash digests.

    In SSZ notation: `List[Vector[Fp, HASH_DIGEST_LENGTH], NODE_LIST_LIMIT]`

    This type is used to represent collections of hash digests in the XMSS scheme.
    """

    ELEMENT_TYPE = HashDigestVector
    LIMIT = NODE_LIST_LIMIT

    def __getitem__(self, index: int) -> HashDigestVector:
        """Access a hash digest by index with proper typing."""
        return self.data[index]  # type: ignore[return-value]


class Parameter(SSZVector):
    """
    The public parameter P.

    This is a unique, randomly generated value associated with a single key pair. It
    is mixed into every hash computation to "personalize" the hash function, preventing
    certain cross-key attacks. It is public knowledge.
    """

    ELEMENT_TYPE = Fp
    LENGTH = TARGET_CONFIG.PARAMETER_LEN

    @property
    def elements(self) -> List[Fp]:
        """Return the field elements as a typed list."""
        return list(self.data)  # type: ignore[arg-type]


class Randomness(SSZVector):
    """
    The randomness `rho` (ρ) used during signing.

    This value provides a variable input to the message hash, allowing the signer to
    repeatedly try hashing until a valid "codeword" is found. It must be included in
    the final signature for the verifier to reproduce the same hash.

    SSZ notation: `Vector[Fp, RAND_LEN_FE]`
    """

    ELEMENT_TYPE = Fp
    LENGTH = TARGET_CONFIG.RAND_LEN_FE


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


LAYERS_LIMIT = TARGET_CONFIG.LOG_LIFETIME + 1
"""
The maximum number of layers in a subtree.

This is `LOG_LIFETIME + 1` to accommodate all layers from 0 (leaves) to LOG_LIFETIME (root),
inclusive. For example, with LOG_LIFETIME=32, this allows up to 33 layers.
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

    def __getitem__(self, index: int) -> HashTreeLayer:
        """Access a layer by index with proper typing."""
        return self.data[index]  # type: ignore[return-value]
