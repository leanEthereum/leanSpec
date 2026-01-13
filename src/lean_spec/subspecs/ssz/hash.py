"""
SSZ Merkleization entry point (`hash_tree_root`).

This module exposes a `hash_tree_root(value: object) -> Bytes32` singledispatch function.
"""

from __future__ import annotations

from functools import singledispatch
from math import ceil

from lean_spec.subspecs.ssz.constants import BYTES_PER_CHUNK
from lean_spec.types.bitfields import BaseBitlist, BaseBitvector
from lean_spec.types.boolean import Boolean
from lean_spec.types.byte_arrays import BaseByteList, BaseBytes, Bytes32
from lean_spec.types.collections import (
    SSZList,
    SSZVector,
)
from lean_spec.types.container import Container
from lean_spec.types.uint import BaseUint
from lean_spec.types.union import SSZUnion

from .merkleization import merkleize, mix_in_length, mix_in_selector
from .pack import pack_bits, pack_bytes


@singledispatch
def hash_tree_root(value: object) -> Bytes32:
    """
    Compute `hash_tree_root(value)` for SSZ values.

    Concrete specializations are registered below with `@hash_tree_root.register(Type)`.

    Raises:
        TypeError: If `value` has no registered specialization.
    """
    raise TypeError(f"hash_tree_root: unsupported value type {type(value).__name__}")


@hash_tree_root.register
def _htr_uint(value: BaseUint) -> Bytes32:
    """Basic scalars merkleize as `merkleize(pack(bytes))`."""
    return merkleize(pack_bytes(value.encode_bytes()))


@hash_tree_root.register
def _htr_boolean(value: Boolean) -> Bytes32:
    return merkleize(pack_bytes(value.encode_bytes()))


@hash_tree_root.register
def _htr_bytes(value: bytes) -> Bytes32:
    """Treat raw bytes like ByteVector[N]."""
    return merkleize(pack_bytes(value))


@hash_tree_root.register
def _htr_bytearray(value: bytearray) -> Bytes32:
    return merkleize(pack_bytes(bytes(value)))


@hash_tree_root.register
def _htr_memoryview(value: memoryview) -> Bytes32:
    return merkleize(pack_bytes(value.tobytes()))


@hash_tree_root.register
def _htr_bytevector(value: BaseBytes) -> Bytes32:
    return merkleize(pack_bytes(value.encode_bytes()))


@hash_tree_root.register
def _htr_bytelist(value: BaseByteList) -> Bytes32:
    data = value.encode_bytes()
    # Compute limit in chunks and merkleize the packed bytes
    limit_chunks = ceil(type(value).LIMIT / BYTES_PER_CHUNK)
    # Mix in the length of the data
    return mix_in_length(merkleize(pack_bytes(data), limit=limit_chunks), len(data))


@hash_tree_root.register
def _htr_bitvector_base(value: BaseBitvector) -> Bytes32:
    # Compute limit in chunks: (nbits + 255) // 256
    limit = (type(value).LENGTH + 255) // 256
    # Pack bits and merkleize with the computed limit
    return merkleize(pack_bits(tuple(bool(b) for b in value.data)), limit=limit)


@hash_tree_root.register
def _htr_bitlist_base(value: BaseBitlist) -> Bytes32:
    # Compute limit in chunks: (LIMIT + 255) // 256
    limit = (type(value).LIMIT + 255) // 256
    # Pack bits, merkleize, and mix in the length
    return mix_in_length(
        merkleize(pack_bits(tuple(bool(b) for b in value.data)), limit=limit),
        len(value.data),
    )


@hash_tree_root.register
def _htr_vector(value: SSZVector) -> Bytes32:
    elem_t, length = type(value).ELEMENT_TYPE, type(value).LENGTH

    if issubclass(elem_t, (BaseUint, Boolean)):
        # BASIC elements: pack serialized bytes
        elem_size = elem_t.get_byte_length() if issubclass(elem_t, BaseUint) else 1
        # Compute limit in chunks: ceil((length * elem_size) / BYTES_PER_CHUNK)
        limit_chunks = (length * elem_size + BYTES_PER_CHUNK - 1) // BYTES_PER_CHUNK
        return merkleize(
            pack_bytes(b"".join(e.encode_bytes() for e in value)),
            limit=limit_chunks,
        )

    # COMPOSITE elements: merkleize child roots with limit = length
    return merkleize([hash_tree_root(e) for e in value], limit=length)


@hash_tree_root.register
def _htr_list(value: SSZList) -> Bytes32:
    elem_t, limit = type(value).ELEMENT_TYPE, type(value).LIMIT

    if issubclass(elem_t, (BaseUint, Boolean)):
        # BASIC elements: pack serialized bytes
        elem_size = elem_t.get_byte_length() if issubclass(elem_t, BaseUint) else 1
        # Compute limit in chunks: ceil((limit * elem_size) / BYTES_PER_CHUNK)
        limit_chunks = (limit * elem_size + BYTES_PER_CHUNK - 1) // BYTES_PER_CHUNK
        root = merkleize(
            pack_bytes(b"".join(e.encode_bytes() for e in value)),
            limit=limit_chunks,
        )
    else:
        # COMPOSITE elements: merkleize child roots
        root = merkleize([hash_tree_root(e) for e in value], limit=limit)

    # Mix in the length for both cases
    return mix_in_length(root, len(value))


@hash_tree_root.register
def _htr_container(value: Container) -> Bytes32:
    # Preserve declared field order from the Pydantic model
    return merkleize(
        [hash_tree_root(getattr(value, fname)) for fname in type(value).model_fields.keys()]
    )


@hash_tree_root.register
def _htr_union(value: SSZUnion) -> Bytes32:
    if value.selected_type is None:
        return mix_in_selector(Bytes32.zero(), 0)
    return mix_in_selector(hash_tree_root(value.value), value.selector)
