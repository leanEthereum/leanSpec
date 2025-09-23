"""
SSZ Merkleization entry point (`hash_tree_root`).

This module exposes:
- A `hash_tree_root(value: object) -> Bytes32` singledispatch function.
- A tiny facade `HashTreeRoot.compute(value)` if you prefer a class entrypoint.
"""

from __future__ import annotations

from functools import singledispatch
from math import ceil
from typing import Final, Type

from lean_spec.subspecs.ssz.constants import BYTES_PER_CHUNK
from lean_spec.types.bitfields import Bitlist, BitlistBase, Bitvector, BitvectorBase
from lean_spec.types.boolean import Boolean
from lean_spec.types.byte_arrays import BaseBytes, ByteListBase, Bytes32
from lean_spec.types.collections import (
    SSZList,
    SSZVector,
)
from lean_spec.types.container import Container
from lean_spec.types.uint import BaseUint
from lean_spec.types.union import Union

from .merkleization import Merkle
from .pack import Packer


@singledispatch
def hash_tree_root(value: object) -> Bytes32:
    """
    Compute `hash_tree_root(value)` for SSZ values.

    Concrete specializations are registered below with `@hash_tree_root.register(Type)`.

    Raises:
        TypeError: If `value` has no registered specialization.
    """
    raise TypeError(f"hash_tree_root: unsupported value type {type(value).__name__}")


class HashTreeRoot:
    """OO facade around `hash_tree_root`."""

    @staticmethod
    def compute(value: object) -> Bytes32:
        """Delegate to the singledispatch implementation."""
        return hash_tree_root(value)


@hash_tree_root.register
def _htr_uint(value: BaseUint) -> Bytes32:
    """Basic scalars merkleize as `merkleize(pack(bytes))`."""
    return Merkle.merkleize(Packer.pack_bytes(value.encode_bytes()))


@hash_tree_root.register
def _htr_boolean(value: Boolean) -> Bytes32:
    return Merkle.merkleize(Packer.pack_bytes(value.encode_bytes()))


@hash_tree_root.register
def _htr_bytes(value: bytes) -> Bytes32:
    """Treat raw bytes like ByteVector[N]."""
    return Merkle.merkleize(Packer.pack_bytes(value))


@hash_tree_root.register
def _htr_bytearray(value: bytearray) -> Bytes32:
    return Merkle.merkleize(Packer.pack_bytes(bytes(value)))


@hash_tree_root.register
def _htr_memoryview(value: memoryview) -> Bytes32:
    data: Final[bytes] = value.tobytes()
    return Merkle.merkleize(Packer.pack_bytes(data))


@hash_tree_root.register
def _htr_bytevector(value: BaseBytes) -> Bytes32:
    return Merkle.merkleize(Packer.pack_bytes(value.encode_bytes()))


@hash_tree_root.register
def _htr_bytelist(value: ByteListBase) -> Bytes32:
    data = value.encode_bytes()
    limit_chunks = ceil(type(value).LIMIT / BYTES_PER_CHUNK)
    root = Merkle.merkleize(Packer.pack_bytes(data), limit=limit_chunks)
    return Merkle.mix_in_length(root, len(data))


@hash_tree_root.register
def _htr_bitvector(value: Bitvector) -> Bytes32:
    nbits = type(value).LENGTH
    limit = (nbits + 255) // 256
    chunks = Packer.pack_bits(tuple(bool(b) for b in value))
    return Merkle.merkleize(chunks, limit=limit)


@hash_tree_root.register
def _htr_bitlist(value: Bitlist) -> Bytes32:
    limit = (type(value).LIMIT + 255) // 256
    chunks = Packer.pack_bits(tuple(bool(b) for b in value))
    root = Merkle.merkleize(chunks, limit=limit)
    return Merkle.mix_in_length(root, len(value))


@hash_tree_root.register
def _htr_bitvector_base(value: BitvectorBase) -> Bytes32:
    nbits = type(value).LENGTH
    limit = (nbits + 255) // 256
    chunks = Packer.pack_bits(tuple(bool(b) for b in value.data))
    return Merkle.merkleize(chunks, limit=limit)


@hash_tree_root.register
def _htr_bitlist_base(value: BitlistBase) -> Bytes32:
    limit = (type(value).LIMIT + 255) // 256
    chunks = Packer.pack_bits(tuple(bool(b) for b in value.data))
    root = Merkle.merkleize(chunks, limit=limit)
    return Merkle.mix_in_length(root, len(value.data))


@hash_tree_root.register
def _htr_vector(value: SSZVector) -> Bytes32:
    elem_t: Type[object] = type(value).ELEMENT_TYPE
    length: int = type(value).LENGTH

    # BASIC elements (uint/boolean): pack serialized bytes
    if issubclass(elem_t, (BaseUint, Boolean)):
        elem_size = elem_t.get_byte_length() if issubclass(elem_t, BaseUint) else 1
        concat = b"".join(e.encode_bytes() for e in value)
        limit_chunks = (length * elem_size + (BYTES_PER_CHUNK - 1)) // BYTES_PER_CHUNK
        return Merkle.merkleize(Packer.pack_bytes(concat), limit=limit_chunks)

    # COMPOSITE elements: merkleize child roots with limit = length
    leaves = [hash_tree_root(e) for e in value]
    return Merkle.merkleize(leaves, limit=length)


@hash_tree_root.register
def _htr_list(value: SSZList) -> Bytes32:
    elem_t: Type[object] = type(value).ELEMENT_TYPE
    limit: int = type(value).LIMIT

    # BASIC elements
    if issubclass(elem_t, (BaseUint, Boolean)):
        elem_size = elem_t.get_byte_length() if issubclass(elem_t, BaseUint) else 1
        concat = b"".join(e.encode_bytes() for e in value)
        limit_chunks = (limit * elem_size + (BYTES_PER_CHUNK - 1)) // BYTES_PER_CHUNK
        root = Merkle.merkleize(Packer.pack_bytes(concat), limit=limit_chunks)
        return Merkle.mix_in_length(root, len(value))

    # COMPOSITE elements
    leaves = [hash_tree_root(e) for e in value]
    root = Merkle.merkleize(leaves, limit=limit)
    return Merkle.mix_in_length(root, len(value))


@hash_tree_root.register
def _htr_container(value: Container) -> Bytes32:
    # Preserve declared field order from the Pydantic model.
    leaves = [hash_tree_root(getattr(value, fname)) for fname in type(value).model_fields.keys()]
    return Merkle.merkleize(leaves)


@hash_tree_root.register
def _htr_union(value: Union) -> Bytes32:
    sel = value.selector
    if value.selected_type is None:
        return Merkle.mix_in_selector(Bytes32.zero(), 0)
    return Merkle.mix_in_selector(hash_tree_root(value.value), sel)
