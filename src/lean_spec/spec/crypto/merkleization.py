"""Merkleization primitives and hash-tree-root dispatch for SSZ."""

from __future__ import annotations

import math
from collections.abc import Sequence
from functools import singledispatch
from hashlib import sha256
from itertools import accumulate, batched, repeat
from typing import Final

from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.ssz import ZERO_HASH
from lean_spec.spec.ssz.bitfields import BaseBitlist, BaseBitvector
from lean_spec.spec.ssz.boolean import Boolean
from lean_spec.spec.ssz.byte_arrays import BaseByteList, BaseBytes, Bytes32
from lean_spec.spec.ssz.collections import SSZList, SSZVector
from lean_spec.spec.ssz.container import Container
from lean_spec.spec.ssz.uint import BaseUint

BYTES_PER_CHUNK: Final = 32
"""Width of a Merkle leaf chunk in bytes."""

BITS_PER_CHUNK: Final = BYTES_PER_CHUNK * 8
"""Width of a Merkle leaf chunk in bits."""


def _next_pow2(x: int) -> int:
    """
    Smallest power of two greater than or equal to x.

    Returns 1 when x is 0 or 1.
    """
    if x <= 1:
        return 1
    return 1 << (x - 1).bit_length()


_ZERO_HASHES: Final[tuple[Bytes32, ...]] = tuple(
    accumulate(
        repeat(None, 64),
        lambda previous, _: Bytes32(sha256(previous + previous).digest()),
        initial=ZERO_HASH,
    )
)
"""
Roots of perfect zero subtrees, indexed by depth.

- Index 0 is the all-zero leaf.
- Index d is the root of a perfect binary tree of 2**d zero leaves.

Depth 64 covers any chunk count the protocol uses.
"""


def _zero_tree_root(width: int) -> Bytes32:
    """
    Root of an all-zero perfect binary tree with the given leaf count.

    The width must be a power of two.
    """
    # A single-leaf tree has no parent to hash; the root is the leaf itself.
    if width <= 1:
        return ZERO_HASH
    # A perfect binary tree with 2**d leaves has depth d.
    #
    # Subtract one before taking bit_length so a power of two maps to its own depth.
    # - Width 2 -> depth 1,
    # - Width 4 -> depth 2,
    # - Width 1024 -> depth 10,
    # - And so on.
    depth = (width - 1).bit_length()
    # The cache stores the all-zero subtree root at every depth.
    # Index by depth to skip materializing 2**d zero leaves and the layers above them.
    return _ZERO_HASHES[depth]


def merkleize(chunks: Sequence[Bytes32], limit: int | None = None) -> Bytes32:
    r"""
    Compute the SSZ Merkle root over a chunk sequence.

    Tree layout for three leaves with no limit:

        leaves   :  c0     c1     c2     ZERO     (padded to next power of two)
                     \____/        \______/
                       h01        h(c2, ZERO)
                        \______________/
                              root

    When a limit is provided, the tree width is the next power of two of that limit.
    Missing leaves contribute pre-computed zero subtree roots instead of
    materialized zero chunks, so allocation stays proportional to actual data.

    Args:
        chunks: Leaf chunks, each exactly 32 bytes wide.
        limit: Optional leaf-count capacity; tree width is rounded up to the next power of two.

    Returns:
        The Merkle root.

    Raises:
        ValueError: If the chunk count exceeds the limit.
    """
    chunk_count = len(chunks)
    if chunk_count == 0:
        return _zero_tree_root(_next_pow2(limit)) if limit is not None else ZERO_HASH
    if limit is None:
        width = _next_pow2(chunk_count)
    elif limit < chunk_count:
        raise ValueError("merkleize: input exceeds limit")
    else:
        width = _next_pow2(limit)
    if width == 1:
        return chunks[0]

    # Walk one tree layer per outer iteration.
    # A missing right sibling pulls the all-zero subtree of the current size from the cache,
    # so unused zero leaves are never allocated.
    level: list[Bytes32] = list(chunks)
    subtree_size = 1
    while subtree_size < width:
        next_level: list[Bytes32] = []
        # Each pair holds the left and right child of one parent node.
        # An odd tail yields a length-one tuple.
        # Its missing right sibling is the all-zero subtree of the current size.
        for child_pair in batched(level, 2):
            left = child_pair[0]
            right = child_pair[1] if len(child_pair) == 2 else _zero_tree_root(subtree_size)
            next_level.append(Bytes32(sha256(left + right).digest()))
        level = next_level
        subtree_size *= 2

    # Invariant: width is the next power of two of the leaf count or capacity,
    # so the loop above halves the level count down to exactly one root.
    assert len(level) == 1
    return level[0]


def mix_in_length(root: Bytes32, length: int) -> Bytes32:
    """
    Mix a length into a Merkle root via the SSZ uint256 little-endian encoding.

    Variable-length types append their declared length to disambiguate roots.
    Two lists with identical elements but different lengths must produce different roots.

    Args:
        root: Merkle root over the data chunks.
        length: Non-negative count to mix in.

    Returns:
        The length-mixed root.

    Raises:
        ValueError: If the length is negative.
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    return Bytes32(sha256(root + length.to_bytes(32, "little")).digest())


def _pack_bytes(data: bytes) -> list[Bytes32]:
    """
    Right-pad serialized bytes to a chunk boundary and split into chunks.

    Layout for a 5-byte payload:

        bytes    :  01 02 03 04 05
        padded   :  01 02 03 04 05 00 00 ... 00     (zero-padded to 32 bytes)
        chunks   :  [ Bytes32(01 02 03 04 05 00 ...) ]

    Inner chunks are already chunk-aligned; only the trailing chunk is padded.
    """
    return [
        Bytes32(data[i : i + BYTES_PER_CHUNK].ljust(BYTES_PER_CHUNK, b"\x00"))
        for i in range(0, len(data), BYTES_PER_CHUNK)
    ]


def _pack_bits(bits: Sequence[Boolean]) -> list[Bytes32]:
    """
    Pack a boolean sequence into bytes, then into chunks for merkleization.

    The first input bit becomes the least significant bit of the first byte.
    Each next input bit moves up one position, wrapping to the next byte after eight.

    Layout for [1, 0, 1, 1]:

        bit position  :   7  6  5  4  3  2  1  0
        byte 0        :   0  0  0  0  1  1  0  1
                                      ^  ^  ^  ^
                                      3  2  1  0   <- input order

    The SSZ serialization delimiter and the length-mix are separate steps,
    handled by the caller when needed.
    """
    packed_bits = sum(1 << i for i, bit in enumerate(bits) if bit)
    return _pack_bytes(packed_bits.to_bytes(math.ceil(len(bits) / 8), "little"))


@singledispatch
def hash_tree_root(value: object) -> Bytes32:
    """
    Compute the SSZ Merkle root of a value.

    Raises:
        TypeError: If the value's type has no registered handler.
    """
    raise TypeError(f"hash_tree_root: unsupported value type {type(value).__name__}")


@hash_tree_root.register(BaseUint)
@hash_tree_root.register(Boolean)
@hash_tree_root.register(Fp)
@hash_tree_root.register(BaseBytes)
def _hash_tree_root_packed_leaf(value: BaseUint | Boolean | Fp | BaseBytes) -> Bytes32:
    # Each of these encodes to a fixed-width byte string with no length prefix.
    # The root is the Merkle root of those bytes packed into 32-byte chunks.
    return merkleize(_pack_bytes(value.encode_bytes()))


@hash_tree_root.register
def _hash_tree_root_bytes(value: bytes) -> Bytes32:
    return merkleize(_pack_bytes(value))


@hash_tree_root.register
def _hash_tree_root_bytelist(value: BaseByteList) -> Bytes32:
    serialized_bytes = value.encode_bytes()
    limit_chunks = math.ceil(type(value).LIMIT / BYTES_PER_CHUNK)
    return mix_in_length(
        merkleize(_pack_bytes(serialized_bytes), limit=limit_chunks), len(serialized_bytes)
    )


@hash_tree_root.register
def _hash_tree_root_bitvector_base(value: BaseBitvector) -> Bytes32:
    limit = math.ceil(type(value).LENGTH / BITS_PER_CHUNK)
    return merkleize(_pack_bits(value.data), limit=limit)


@hash_tree_root.register
def _hash_tree_root_bitlist_base(value: BaseBitlist) -> Bytes32:
    limit = math.ceil(type(value).LIMIT / BITS_PER_CHUNK)
    return mix_in_length(
        merkleize(_pack_bits(value.data), limit=limit),
        len(value.data),
    )


@hash_tree_root.register
def _hash_tree_root_vector(value: SSZVector) -> Bytes32:
    cls = type(value)
    element_type, length = cls.ELEMENT_TYPE, cls.LENGTH
    if issubclass(element_type, (BaseUint, Boolean, Fp)):
        # Basic elements pack their serialized bytes into a single byte stream before chunking.
        element_size = element_type.get_byte_length()
        limit_chunks = math.ceil(length * element_size / BYTES_PER_CHUNK)
        return merkleize(
            _pack_bytes(b"".join(e.encode_bytes() for e in value)),
            limit=limit_chunks,
        )
    # Composite elements each contribute their own hash tree root as a leaf.
    return merkleize([hash_tree_root(e) for e in value], limit=length)


@hash_tree_root.register
def _hash_tree_root_list(value: SSZList) -> Bytes32:
    cls = type(value)
    element_type, limit = cls.ELEMENT_TYPE, cls.LIMIT
    if issubclass(element_type, (BaseUint, Boolean, Fp)):
        element_size = element_type.get_byte_length()
        limit_chunks = math.ceil(limit * element_size / BYTES_PER_CHUNK)
        root = merkleize(
            _pack_bytes(b"".join(e.encode_bytes() for e in value)),
            limit=limit_chunks,
        )
    else:
        root = merkleize([hash_tree_root(e) for e in value], limit=limit)
    return mix_in_length(root, len(value))


@hash_tree_root.register
def _hash_tree_root_container(value: Container) -> Bytes32:
    # Pydantic preserves declaration order, which is the canonical SSZ field order.
    cls = type(value)
    return merkleize([hash_tree_root(getattr(value, name)) for name in cls.model_fields])
