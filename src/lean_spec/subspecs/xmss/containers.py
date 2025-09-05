"""Defines the data containers for the Generalized XMSS signature scheme."""

from typing import Annotated, List

from pydantic import BaseModel, ConfigDict, Field

from ..koalabear import Fp
from .constants import PRF_KEY_LENGTH

PRFKey = Annotated[bytes, Field(min_length=PRF_KEY_LENGTH, max_length=PRF_KEY_LENGTH)]
"""
A type alias for the PRF **master secret key**.

This is a high-entropy byte string that acts as the single root secret from
which all one-time signing keys are deterministically derived.
"""


HashDigest = List[Fp]
"""
A type alias representing a hash digest.

In this scheme, a digest is the output of the Poseidon2 hash function. It is a
fixed-length list of field elements (`Fp`) and serves as the fundamental
building block for all cryptographic structures (e.g., a node in a Merkle tree).
"""

Parameter = List[Fp]
"""
A type alias for the public parameter `P`.

This is a unique, randomly generated value associated with a single key pair. It
is mixed into every hash computation to "personalize" the hash function, preventing
certain cross-key attacks. It is public knowledge.
"""

Randomness = List[Fp]
"""
A type alias for the randomness `rho` (ρ) used during signing.

This value provides a variable input to the message hash, allowing the signer to
repeatedly try hashing until a valid "codeword" is found. It must be included in
the final signature for the verifier to reproduce the same hash.
"""


class HashTreeOpening(BaseModel):
    """
    A Merkle authentication path.

    This object contains the minimal proof required to connect a specific leaf
    to the Merkle root. It consists of the list of all sibling nodes along the
    path from the leaf to the top of the tree.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    siblings: List[HashDigest]
    """List of sibling hashes, from bottom to top."""


class HashTreeLayer(BaseModel):
    """
    Represents a single horizontal "slice" of the sparse Merkle tree.

    Because the tree is sparse, we only store the nodes that are actually computed
    for the active range of leaves, not the entire conceptual layer.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    start_index: int
    """The starting index of the first node in this layer."""
    nodes: List[HashDigest]
    """A list of the actual hash digests stored for this layer."""


class HashTree(BaseModel):
    """
    The pre-computed, stored portion of the sparse Merkle tree.

    This structure is part of the `SecretKey` and contains all the necessary nodes
    to generate an authentication path for any signature within the key's active lifetime.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    depth: int
    """The total depth of the tree (e.g., 32 for a 2^32 leaf space)."""
    layers: List[HashTreeLayer]
    """
    A list of `HashTreeLayer` objects, from the leaf hashes
    (layer 0) up to the layer just below the root.
    """


class PublicKey(BaseModel):
    """
    The public-facing component of a key pair.

    This is the data a verifier needs to check signatures. It is compact, safe to
    distribute publicly, and acts as the signer's identity.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    root: List[Fp]
    """The Merkle root, which commits to all one-time keys for the key's lifetime."""
    parameter: Parameter
    """The public parameter `P` that personalizes the hash function."""


class Signature(BaseModel):
    """
    A signature produced by the `sign` function.

    It contains all the necessary components for a verifier to confirm that a
    specific message was signed by the owner of a `PublicKey` for a specific epoch.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    path: HashTreeOpening
    """The authentication path proving the one-time key's inclusion in the Merkle tree."""
    rho: Randomness
    """The randomness used to successfully encode the message."""
    hashes: List[HashDigest]
    """The one-time signature itself: a list of intermediate Winternitz chain hashes."""


class SecretKey(BaseModel):
    """
    The private component of a key pair. **MUST BE KEPT CONFIDENTIAL.**

    This object contains all the secret material and pre-computed data needed to
    generate signatures for any epoch within its active lifetime.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    prf_key: PRFKey
    """The master secret key used to derive all one-time secrets."""
    tree: HashTree
    """The pre-computed sparse Merkle tree needed to generate authentication paths."""
    parameter: Parameter
    """The public parameter `P`, stored for convenience during signing."""
    activation_epoch: int
    """The first epoch for which this secret key is valid."""
    num_active_epochs: int
    """The number of consecutive epochs this key can be used for."""
