"""Defines the data structures for the Generalized XMSS signature scheme."""

from typing import Annotated, List

from pydantic import BaseModel, ConfigDict, Field

from ..koalabear import Fp
from .constants import PRF_KEY_LENGTH

PRFKey = Annotated[
    bytes, Field(min_length=PRF_KEY_LENGTH, max_length=PRF_KEY_LENGTH)
]
"""
A type alias for the PRF secret key.

It is a byte string of `PRF_KEY_LENGTH` bytes.
"""


HashDigest = List[Fp]
"""
A type alias representing a hash digest.
"""

Parameter = List[Fp]
"""
A type alias representing the public parameter `P`.
"""

Randomness = List[Fp]
"""
A type alias representing the randomness `rho`.
"""


class HashTreeOpening(BaseModel):
    """
    A Merkle authentication path.

    It contains a list of sibling nodes required to reconstruct the path
    from a leaf node up to the Merkle root.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    siblings: List[HashDigest] = Field(
        ..., description="List of sibling hashes, from bottom to top."
    )


class HashTreeLayer(BaseModel):
    """
    Represents a single layer within the sparse Merkle tree.

    Attributes:
        start_index: The index of the first node in this layer within the full
        conceptual tree.
        nodes: A list of the actual hash digests stored for this layer.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    start_index: int
    """The starting index of the first node in this layer."""
    nodes: List[HashDigest]
    """A list of the actual hash digests stored for this layer."""


class HashTree(BaseModel):
    """
    The complete sparse Merkle tree structure.

    Attributes:
        depth: The total depth of the tree (e.g., 32 for a 2^32 leaf space).
        layers: A list of `HashTreeLayer` objects, from the leaf hashes
        (layer 0) up to the layer just below the root.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    depth: int
    """The total depth of the tree (e.g., 32 for a 2^32 leaf space)."""
    layers: List[HashTreeLayer]
    """""A list of `HashTreeLayer` objects, from the leaf hashes
    (layer 0) up to the layer just below the root."""


class PublicKey(BaseModel):
    """The public key for the Generalized XMSS scheme."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    root: List[Fp]
    parameter: Parameter


class Signature(BaseModel):
    """A signature in the Generalized XMSS scheme."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    path: HashTreeOpening
    rho: Randomness
    hashes: List[HashDigest]


class SecretKey(BaseModel):
    """The secret key for the Generalized XMSS scheme."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    prf_key: PRFKey
    tree: HashTree
    parameter: Parameter
    activation_epoch: int
    num_active_epochs: int
