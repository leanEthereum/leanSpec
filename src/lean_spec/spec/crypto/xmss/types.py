"""Base types for the XMSS signature scheme."""

from typing import Final, NamedTuple

from ssz import Uint64

from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.xmss.constants import TARGET_CONFIG
from lean_spec.spec.ssz_types import Container, List, Vector


class TreeTweak(NamedTuple):
    """Tweak that domain-separates Merkle node hashes by their position."""

    level: int
    """Height in the Merkle tree.

    Layer 0 is the leaf level.
    """

    index: Uint64
    """Node index within its level, counted from the left."""


class ChainTweak(NamedTuple):
    """Tweak that domain-separates Winternitz chain hashes by their position."""

    epoch: Uint64
    """Slot identifier for the one-time signature."""

    chain_index: int
    """Index of the chain within the one-time signature."""

    step: int
    """Step number along the chain, 1-indexed; step zero is the chain start."""


NODE_LIST_LIMIT: Final = 2 * TARGET_CONFIG.LEAVES_PER_BOTTOM_TREE
"""
Maximum number of nodes a sparse Merkle tree layer can hold.

- The widest layer is a bottom tree's leaf row, the square root of the lifetime in leaves.
- Padding adds at most one sibling at each end.
- Twice the leaf count is a generous cap that absorbs the padding with room to spare.
"""


class HashDigestVector(Vector[Fp]):
    """
    A single hash digest as a fixed-size vector of field elements.

    The fixed size lets SSZ pack these back-to-back without per-element offsets.
    """

    LENGTH = TARGET_CONFIG.HASH_LENGTH_FIELD_ELEMENTS
    """One Poseidon digest, measured in field elements."""


class HashDigestList(List[HashDigestVector]):
    """Variable-length list of hash digests."""

    LIMIT = NODE_LIST_LIMIT


class Parameter(Vector[Fp]):
    """
    The public parameter P.

    - Unique, randomly generated value associated with a single key pair.
    - Mixed into every hash to personalize the function and block cross-key attacks.
    - Public knowledge.
    """

    LENGTH = TARGET_CONFIG.PARAMETER_LENGTH


class Randomness(Vector[Fp]):
    """
    Fresh randomness mixed into the message hash during signing.

    - Signing rehashes the message with new randomness on each attempt.
    - Retries continue until the resulting codeword hits the target sum.
    - The chosen randomness travels in the signature so the verifier recomputes the same codeword.
    """

    LENGTH = TARGET_CONFIG.RAND_LENGTH_FIELD_ELEMENTS


class HashTreeOpening(Container):
    """
    A Merkle authentication path proving one leaf sits under the root.

    - The path lists the sibling hashes met while climbing from the leaf up to the root.
    - A verifier rehashes the leaf upward with these siblings.
    - The reconstructed root must equal the trusted root.
    """

    siblings: HashDigestList
    """Sibling hashes, ordered from the leaf upward to the root."""
