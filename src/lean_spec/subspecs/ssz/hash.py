"""Hash tree root dispatch for SSZ values."""

from __future__ import annotations

from collections.abc import Sequence
from functools import singledispatch
from math import ceil

from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.ssz.constants import BITS_PER_CHUNK, BYTES_PER_CHUNK
from lean_spec.types.bitfields import BaseBitlist, BaseBitvector
from lean_spec.types.boolean import Boolean
from lean_spec.types.byte_arrays import BaseByteList, BaseBytes, Bytes32
from lean_spec.types.collections import SSZList, SSZVector
from lean_spec.types.container import Container
from lean_spec.types.uint import BaseUint

from .merkleization import merkleize, mix_in_length


def _pack_bytes(data: bytes) -> list[Bytes32]:
    """Right-pad serialized bytes to a chunk boundary and split into chunks.

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
    """Pack a boolean sequence into bytes, then into chunks for merkleization.

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
    value = sum(1 << i for i, bit in enumerate(bits) if bit)
    return _pack_bytes(value.to_bytes(ceil(len(bits) / 8), "little"))


@singledispatch
def hash_tree_root(value: object) -> Bytes32:
    """Compute the SSZ Merkle root of a value.

    Raises:
        TypeError: If the value's type has no registered handler.
    """
    raise TypeError(f"hash_tree_root: unsupported value type {type(value).__name__}")


@hash_tree_root.register
def _htr_uint(value: BaseUint) -> Bytes32:
    return merkleize(_pack_bytes(value.encode_bytes()))


@hash_tree_root.register
def _htr_boolean(value: Boolean) -> Bytes32:
    return merkleize(_pack_bytes(value.encode_bytes()))


@hash_tree_root.register
def _htr_fp(value: Fp) -> Bytes32:
    return merkleize(_pack_bytes(value.encode_bytes()))


@hash_tree_root.register
def _htr_bytes(value: bytes) -> Bytes32:
    return merkleize(_pack_bytes(value))


@hash_tree_root.register
def _htr_bytearray(value: bytearray) -> Bytes32:
    return merkleize(_pack_bytes(bytes(value)))


@hash_tree_root.register
def _htr_memoryview(value: memoryview) -> Bytes32:
    return merkleize(_pack_bytes(value.tobytes()))


@hash_tree_root.register
def _htr_bytevector(value: BaseBytes) -> Bytes32:
    return merkleize(_pack_bytes(value.encode_bytes()))


@hash_tree_root.register
def _htr_bytelist(value: BaseByteList) -> Bytes32:
    data = value.encode_bytes()
    limit_chunks = ceil(type(value).LIMIT / BYTES_PER_CHUNK)
    return mix_in_length(merkleize(_pack_bytes(data), limit=limit_chunks), len(data))


@hash_tree_root.register
def _htr_bitvector_base(value: BaseBitvector) -> Bytes32:
    limit = ceil(type(value).LENGTH / BITS_PER_CHUNK)
    return merkleize(_pack_bits(value.data), limit=limit)


@hash_tree_root.register
def _htr_bitlist_base(value: BaseBitlist) -> Bytes32:
    limit = ceil(type(value).LIMIT / BITS_PER_CHUNK)
    return mix_in_length(
        merkleize(_pack_bits(value.data), limit=limit),
        len(value.data),
    )


@hash_tree_root.register
def _htr_vector(value: SSZVector) -> Bytes32:
    cls = type(value)
    elem_t, length = cls.ELEMENT_TYPE, cls.LENGTH
    if issubclass(elem_t, (BaseUint, Boolean, Fp)):
        # Basic elements pack their serialized bytes into a single byte stream before chunking.
        elem_size = elem_t.get_byte_length()
        limit_chunks = ceil(length * elem_size / BYTES_PER_CHUNK)
        return merkleize(
            _pack_bytes(b"".join(e.encode_bytes() for e in value)),
            limit=limit_chunks,
        )
    # Composite elements each contribute their own hash tree root as a leaf.
    return merkleize([hash_tree_root(e) for e in value], limit=length)


@hash_tree_root.register
def _htr_list(value: SSZList) -> Bytes32:
    cls = type(value)
    elem_t, limit = cls.ELEMENT_TYPE, cls.LIMIT
    if issubclass(elem_t, (BaseUint, Boolean, Fp)):
        elem_size = elem_t.get_byte_length()
        limit_chunks = ceil(limit * elem_size / BYTES_PER_CHUNK)
        root = merkleize(
            _pack_bytes(b"".join(e.encode_bytes() for e in value)),
            limit=limit_chunks,
        )
    else:
        root = merkleize([hash_tree_root(e) for e in value], limit=limit)
    return mix_in_length(root, len(value))


@hash_tree_root.register
def _htr_container(value: Container) -> Bytes32:
    # Pydantic preserves declaration order, which is the canonical SSZ field order.
    cls = type(value)
    return merkleize([hash_tree_root(getattr(value, name)) for name in cls.model_fields])
