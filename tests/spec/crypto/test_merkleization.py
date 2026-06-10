"""Unit tests for SSZ Merkleization primitives and the hash_tree_root dispatch."""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha256

import pytest

from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.merkleization import (
    _next_pow2,
    _zero_tree_root,
    hash_tree_root,
    merkleize,
    mix_in_length,
)
from lean_spec.spec.ssz import (
    ZERO_HASH,
    BaseByteList,
    BaseBytes,
    Bytes32,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
)
from lean_spec.spec.ssz.bitfields import BaseBitlist, BaseBitvector
from lean_spec.spec.ssz.boolean import Boolean
from lean_spec.spec.ssz.collections import SSZList, SSZVector
from lean_spec.spec.ssz.container import Container


def h(a: bytes, b: bytes) -> Bytes32:
    """Pairwise SHA-256 of two 32-byte nodes; used to build expected roots."""
    return Bytes32(sha256(a + b).digest())


def pad(payload: bytes) -> Bytes32:
    """Right-pad a payload to 32 bytes."""
    return Bytes32(payload.ljust(32, b"\x00"))


def merge(leaf: Bytes32, branch: Iterable[Bytes32]) -> Bytes32:
    """Walk a single leaf up a chain of right siblings, hashing left at each step."""
    running_node = leaf
    for sibling in branch:
        running_node = h(running_node, sibling)
    return running_node


# Sample chunks for testing, sample_chunks[i] = bytes32(i)
sample_chunks = [Bytes32(i.to_bytes(32, "little")) for i in range(16)]

# Pre-calculate zero-tree roots for assertions
# Z[0] = ZERO_HASH, Z[1] = h(Z[0], Z[0]), Z[2] = h(Z[1], Z[1]), etc.
Z = [ZERO_HASH]
for _ in range(20):
    Z.append(h(Z[-1], Z[-1]))


@pytest.mark.parametrize(
    "x, expected",
    [
        (0, 1),  # Edge case: 0 should result in 1
        (1, 1),  # A power of two
        (2, 2),  # A power of two
        (3, 4),  # A number between powers of two
        (4, 4),  # A power of two
        (5, 8),
        (7, 8),
        (8, 8),
        (9, 16),
        (1023, 1024),
        (1024, 1024),  # A larger power of two
    ],
)
def test_next_pow2(x: int, expected: int) -> None:
    """Returns the smallest power of two at or above the input, with 1 for 0 and 1."""
    assert _next_pow2(x) == expected


def test_merkleize_empty_no_limit() -> None:
    """Merkleizing an empty list with no limit returns the all-zero leaf."""
    assert merkleize([]) == ZERO_HASH


@pytest.mark.parametrize(
    "limit, expected_zero_root",
    [
        (0, Z[0]),  # limit=0 -> width=1 -> root is Z[0]
        (1, Z[0]),  # limit=1 -> width=1 -> root is Z[0]
        (2, Z[1]),  # limit=2 -> width=2 -> root is Z[1]
        (3, Z[2]),  # limit=3 -> width=4 -> root is Z[2]
        (7, Z[3]),  # limit=7 -> width=8 -> root is Z[3]
        (8, Z[3]),
    ],
)
def test_merkleize_empty_with_limit(limit: int, expected_zero_root: Bytes32) -> None:
    """Empty input with a limit yields the zero-subtree root at the rounded-up width."""
    assert merkleize([], limit=limit) == expected_zero_root


def test_merkleize_single_chunk() -> None:
    """The root of a single chunk is the chunk itself."""
    assert merkleize([sample_chunks[1]]) == sample_chunks[1]


def test_merkleize_power_of_two_chunks() -> None:
    """A power-of-two leaf count needs no padding."""
    # Test with 2 chunks
    assert merkleize([sample_chunks[0], sample_chunks[1]]) == h(sample_chunks[0], sample_chunks[1])
    # Test with 4 chunks
    root_4 = h(h(sample_chunks[0], sample_chunks[1]), h(sample_chunks[2], sample_chunks[3]))
    assert merkleize(sample_chunks[0:4]) == root_4


def test_merkleize_non_power_of_two_chunks() -> None:
    """A non-power-of-two leaf count pads to the next power of two."""
    # Test with 3 chunks (pads to 4)
    expected_root_3_chunks = h(h(sample_chunks[0], sample_chunks[1]), h(sample_chunks[2], Z[0]))
    assert merkleize(sample_chunks[0:3]) == expected_root_3_chunks
    # Test with 5 chunks (pads to 8)
    h01 = h(sample_chunks[0], sample_chunks[1])
    h23 = h(sample_chunks[2], sample_chunks[3])
    h4z = h(sample_chunks[4], Z[0])
    # The remaining leaves are zero, so their parent is h(Z[0], Z[0]) = Z[1]
    expected_root_5_chunks = h(h(h01, h23), h(h4z, Z[1]))
    assert merkleize(sample_chunks[0:5]) == expected_root_5_chunks


def test_merkleize_with_limit_padding() -> None:
    """A limit larger than the leaf count widens the tree to the next power of two of the limit."""
    # 3 chunks, but limit is 8 (pads to width 8)
    h01 = h(sample_chunks[0], sample_chunks[1])
    h2z = h(sample_chunks[2], Z[0])
    # The parent of h01 and h2z
    left_branch = h(h01, h2z)
    # The right branch is a zero-tree of width 4, so its root is Z[2].
    right_branch = Z[2]
    expected_root = h(left_branch, right_branch)
    assert merkleize(sample_chunks[0:3], limit=8) == expected_root


def test_merkleize_error_on_exceeding_limit() -> None:
    """Raises when the chunk count exceeds the limit."""
    with pytest.raises(ValueError) as exception_info:
        merkleize(sample_chunks[0:5], limit=4)
    assert str(exception_info.value) == "merkleize: input exceeds limit"


def test_mix_in_length() -> None:
    """Mixes the length encoded as little-endian uint256 into the root."""
    root = sample_chunks[0]
    length = 12345
    length_bytes = Bytes32(length.to_bytes(32, "little"))
    expected_root = h(root, length_bytes)
    assert mix_in_length(root, length) == expected_root


def test_mix_in_length_zero() -> None:
    """Zero is a valid length."""
    root = sample_chunks[0]
    length = 0
    length_bytes = Bytes32(length.to_bytes(32, "little"))
    expected_root = h(root, length_bytes)
    assert mix_in_length(root, length) == expected_root


def test_mix_in_length_error_on_negative() -> None:
    """Rejects negative lengths."""
    with pytest.raises(ValueError):
        mix_in_length(sample_chunks[0], -1)


def test_zero_tree_root_internal() -> None:
    """Returns the cached zero-subtree root at depths within the cache."""
    assert _zero_tree_root(1) == Z[0]
    assert _zero_tree_root(2) == Z[1]
    assert _zero_tree_root(4) == Z[2]
    assert _zero_tree_root(8) == Z[3]
    assert _zero_tree_root(16) == Z[4]


class Bytes48(BaseBytes):
    """Test-local fixed-size byte array of 48 bytes."""

    LENGTH = 48


class Bytes96(BaseBytes):
    """Test-local fixed-size byte array of 96 bytes spanning three chunks."""

    LENGTH = 96


class ByteList7(BaseByteList):
    """Byte list with a single-chunk capacity of 7 bytes."""

    LIMIT = 7


class ByteList10(BaseByteList):
    """Byte list with a single-chunk capacity of 10 bytes."""

    LIMIT = 10


class ByteList32(BaseByteList):
    """Byte list whose capacity exactly fills one chunk."""

    LIMIT = 32


class ByteList50(BaseByteList):
    """Byte list spanning two chunks of capacity."""

    LIMIT = 50


class ByteList256(BaseByteList):
    """Byte list with capacity for eight chunks."""

    LIMIT = 256


class ByteList2048(BaseByteList):
    """Byte list with capacity for sixty-four chunks."""

    LIMIT = 2048


class Bitvector1(BaseBitvector):
    """Single-bit bitvector."""

    LENGTH = 1


class Bitvector3(BaseBitvector):
    """Three-bit bitvector inside one byte."""

    LENGTH = 3


class Bitvector8(BaseBitvector):
    """Bitvector aligned to one byte."""

    LENGTH = 8


class Bitvector9(BaseBitvector):
    """Bitvector spilling into a second byte."""

    LENGTH = 9


class Bitvector256(BaseBitvector):
    """Bitvector whose data fills exactly one 32-byte chunk."""

    LENGTH = 256


class Bitvector512(BaseBitvector):
    """Bitvector whose data fills exactly two chunks."""

    LENGTH = 512


class Bitlist3(BaseBitlist):
    """Bitlist limit of three bits."""

    LIMIT = 3


class Bitlist8(BaseBitlist):
    """Bitlist limit of eight bits."""

    LIMIT = 8


class Bitlist256(BaseBitlist):
    """Bitlist whose data root fits one chunk."""

    LIMIT = 256


class Bitlist512(BaseBitlist):
    """Bitlist whose data root spans two chunks."""

    LIMIT = 512


class Uint16Vector1(SSZVector[Uint16]):
    """Single-element vector of Uint16."""

    LENGTH = 1


class Uint16Vector2(SSZVector[Uint16]):
    """Two-element vector of Uint16."""

    LENGTH = 2


class Uint16Vector16(SSZVector[Uint16]):
    """Sixteen-element vector of Uint16 filling exactly one chunk."""

    LENGTH = 16


class Bytes32Vector3(SSZVector[Bytes32]):
    """Vector of three composite Bytes32 elements."""

    LENGTH = 3


class Uint16List32(SSZList[Uint16]):
    """List of Uint16 with a 32-element limit."""

    LIMIT = 32


class Uint16List1024(SSZList[Uint16]):
    """List of Uint16 with a 1024-element limit used as a container field."""

    LIMIT = 1024


class Uint32List128(SSZList[Uint32]):
    """List of Uint32 with a 128-element limit."""

    LIMIT = 128


class Bytes32List32(SSZList[Bytes32]):
    """List of composite Bytes32 elements with a 32-element limit."""

    LIMIT = 32


class SingleField(Container):
    """Container holding a single basic field."""

    A: Uint8


class Small(Container):
    """Container with two byte-aligned fields fitting in one chunk each."""

    A: Uint16
    B: Uint16


class Fixed(Container):
    """Container with three fixed-size fields needing tree padding."""

    A: Uint8
    B: Uint64
    C: Uint32


class Var(Container):
    """Container with a variable-size middle field."""

    A: Uint16
    B: Uint16List1024
    C: Uint8


class FixedVector4(SSZVector[Fixed]):
    """Vector of four fixed-size containers."""

    LENGTH = 4


class VarVector2(SSZVector[Var]):
    """Vector of two variable-size containers."""

    LENGTH = 2


class EmptyContainer(Container):
    """Container with zero fields."""


def le_padded(integer_value: int, byte_length: int) -> Bytes32:
    """Encode an integer little-endian and right-pad to one chunk."""
    return pad(integer_value.to_bytes(byte_length, "little"))


@pytest.mark.parametrize(
    "uint_type, byte_length, integer_value",
    [
        (Uint8, 1, 0x00),
        (Uint8, 1, 0x01),
        (Uint8, 1, 0xAB),
        (Uint8, 1, 0xFF),
        (Uint16, 2, 0x0000),
        (Uint16, 2, 0xABCD),
        (Uint16, 2, 0xFFFF),
        (Uint32, 4, 0x00000000),
        (Uint32, 4, 0x01234567),
        (Uint32, 4, 0xFFFFFFFF),
        (Uint64, 8, 0x0000000000000000),
        (Uint64, 8, 0x0123456789ABCDEF),
        (Uint64, 8, 0xFFFFFFFFFFFFFFFF),
    ],
)
def test_hash_tree_root_uints(uint_type: type, byte_length: int, integer_value: int) -> None:
    """Unsigned integers hash as their little-endian bytes padded to one chunk."""
    assert hash_tree_root(uint_type(integer_value)) == le_padded(integer_value, byte_length)


@pytest.mark.parametrize(
    "boolean, expected_byte",
    [
        (Boolean(False), b"\x00"),
        (Boolean(True), b"\x01"),
    ],
)
def test_hash_tree_root_boolean(boolean: Boolean, expected_byte: bytes) -> None:
    """Boolean hashes to a single byte padded to one chunk."""
    assert hash_tree_root(boolean) == pad(expected_byte)


@pytest.mark.parametrize(
    "integer_value",
    [
        0,
        1,
        42,
        (1 << 31) - 2**24,  # Largest residue under the KoalaBear modulus.
    ],
)
def test_hash_tree_root_fp(integer_value: int) -> None:
    """KoalaBear field elements hash as their four-byte little-endian encoding."""
    assert hash_tree_root(Fp(integer_value)) == le_padded(integer_value, 4)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00",
        b"\x01",
        b"\xab",
        b"\x00\x01\x02\x03",
        b"\xff" * 31,
        b"\xff" * 32,
        b"\xff" * 33,
    ],
)
def test_hash_tree_root_raw_bytes_like(payload: bytes) -> None:
    """Raw bytes, bytearray, and memoryview hash identically."""
    from_bytes = hash_tree_root(payload)
    from_bytearray = hash_tree_root(bytearray(payload))
    from_memoryview = hash_tree_root(memoryview(payload))
    assert from_bytes == from_bytearray == from_memoryview


@pytest.mark.parametrize(
    "payload, expected_root",
    [
        # Empty: zero chunks merkleizes to the all-zero leaf.
        (b"", Z[0]),
        # One byte fits in one chunk and is its own root.
        (b"\xab", pad(b"\xab")),
        # 31 bytes still hash to a single padded chunk.
        (b"\xff" * 31, pad(b"\xff" * 31)),
        # 32 bytes are exactly one chunk and are their own root.
        (b"\xff" * 32, Bytes32(b"\xff" * 32)),
        # 33 bytes form two chunks; the second is padded.
        (b"\xff" * 32 + b"\x01", h(b"\xff" * 32, pad(b"\x01"))),
        # 64 bytes form two full chunks hashed together.
        (b"\xaa" * 32 + b"\xbb" * 32, h(b"\xaa" * 32, b"\xbb" * 32)),
    ],
)
def test_hash_tree_root_bytes_known_vectors(payload: bytes, expected_root: Bytes32) -> None:
    """Raw byte payloads hash to the merkle root of their packed chunks."""
    assert hash_tree_root(payload) == expected_root


def test_hash_tree_root_bytevector_single_chunk() -> None:
    """A 32-byte vector is exactly one chunk and is its own root."""
    raw_bytes = bytes(range(32))
    assert hash_tree_root(Bytes32(raw_bytes)) == Bytes32(raw_bytes)


def test_hash_tree_root_bytevector_two_chunks() -> None:
    """A 48-byte vector hashes its two chunks together; the trailing chunk is padded."""
    raw_bytes = bytes(range(48))
    expected_root = h(raw_bytes[:32], pad(raw_bytes[32:]))
    assert hash_tree_root(Bytes48(raw_bytes)) == expected_root


def test_hash_tree_root_bytevector_three_chunks() -> None:
    """A 96-byte vector merkleizes its three chunks with a zero pad to width four."""
    raw_bytes = bytes(range(96))
    left = h(raw_bytes[0:32], raw_bytes[32:64])
    right = h(raw_bytes[64:96], Z[0])
    assert hash_tree_root(Bytes96(raw_bytes)) == h(left, right)


def test_hash_tree_root_bytelist_empty_single_chunk_capacity() -> None:
    """An empty list with single-chunk capacity mixes a zero chunk with length zero."""
    expected_root = h(Z[0], pad(b"\x00"))
    assert hash_tree_root(ByteList10(data=b"")) == expected_root


def test_hash_tree_root_bytelist_empty_large_capacity() -> None:
    """An empty list with 64-chunk capacity uses the depth-6 zero root before mix-in."""
    expected_root = h(Z[6], pad(b"\x00"))
    assert hash_tree_root(ByteList2048(data=b"")) == expected_root


@pytest.mark.parametrize(
    "list_cls, payload, expected_root",
    [
        # Small list fits in one chunk; data root is the padded payload.
        (
            ByteList7,
            b"\x00\x01\x02\x03\x04\x05\x06",
            h(pad(b"\x00\x01\x02\x03\x04\x05\x06"), pad(b"\x07")),
        ),
        # Two-chunk capacity holds a 50-byte payload that spans both chunks.
        (
            ByteList50,
            bytes(range(50)),
            h(
                h(bytes(range(32)), pad(bytes(range(32, 50)))),
                pad(b"\x32"),
            ),
        ),
        # Eight-chunk capacity with six bytes pads the lone data chunk to depth three.
        (
            ByteList256,
            b"\x00\x01\x02\x03\x04\x05",
            h(
                merge(pad(b"\x00\x01\x02\x03\x04\x05"), [Z[0], Z[1], Z[2]]),
                pad(b"\x06"),
            ),
        ),
        # Capacity boundary: a full single chunk of data uses the chunk as the data root.
        (
            ByteList32,
            bytes(range(32)),
            h(Bytes32(bytes(range(32))), pad(b"\x20")),
        ),
    ],
)
def test_hash_tree_root_bytelist_various(
    list_cls: type[BaseByteList], payload: bytes, expected_root: Bytes32
) -> None:
    """Variable-length byte lists merkleize their packed data then mix in the length."""
    assert hash_tree_root(list_cls(data=payload)) == expected_root


def _bools(*values: int) -> list[Boolean]:
    """Build a typed boolean sequence from 0/1 integers."""
    return [Boolean(bool(bit)) for bit in values]


@pytest.mark.parametrize(
    "bv_cls, bits, expected_payload",
    [
        # Single bit set produces 0x01 padded.
        (Bitvector1, _bools(1), b"\x01"),
        # Three bits 0,1,0 produce 0b010 = 0x02 padded.
        (Bitvector3, _bools(0, 1, 0), b"\x02"),
        # Eight ones fill one byte at 0xff.
        (Bitvector8, _bools(*([1] * 8)), b"\xff"),
        # Nine ones spill into a second byte at 0x01.
        (Bitvector9, _bools(*([1] * 9)), b"\xff\x01"),
    ],
)
def test_hash_tree_root_bitvector_single_chunk(
    bv_cls: type[BaseBitvector],
    bits: list[Boolean],
    expected_payload: bytes,
) -> None:
    """Small bitvectors merkleize to a single padded chunk of their packed bytes."""
    bv = bv_cls(data=bits)
    assert bv.encode_bytes() == expected_payload
    assert hash_tree_root(bv) == pad(expected_payload)


def test_hash_tree_root_bitvector_one_chunk_boundary() -> None:
    """A 256-bit vector of ones packs into exactly one all-ones chunk."""
    bv = Bitvector256(data=_bools(*([1] * 256)))
    assert hash_tree_root(bv) == Bytes32(b"\xff" * 32)


def test_hash_tree_root_bitvector_two_chunks() -> None:
    """A 512-bit vector of ones hashes two all-ones chunks together."""
    bv = Bitvector512(data=_bools(*([1] * 512)))
    assert hash_tree_root(bv) == h(b"\xff" * 32, b"\xff" * 32)


@pytest.mark.parametrize(
    "bl_cls, bits, expected_data_root, expected_length",
    [
        # Bitlist[3] with 0,1,0 has data byte 0x02 and length 3.
        (Bitlist3, _bools(0, 1, 0), pad(b"\x02"), 3),
        # Bitlist[8] with all ones has data byte 0xff and length 8.
        (Bitlist8, _bools(*([1] * 8)), pad(b"\xff"), 8),
        # Bitlist[8] empty: data root is the zero chunk and length is 0.
        (Bitlist8, _bools(), Z[0], 0),
    ],
)
def test_hash_tree_root_bitlist_small(
    bl_cls: type[BaseBitlist],
    bits: list[Boolean],
    expected_data_root: Bytes32,
    expected_length: int,
) -> None:
    """Short bitlists hash the data chunk and mix in the bit count."""
    bl = bl_cls(data=bits)
    expected_root = h(expected_data_root, pad(expected_length.to_bytes(32, "little")))
    assert hash_tree_root(bl) == expected_root


def test_hash_tree_root_bitlist_chunk_boundary() -> None:
    """A bitlist whose data fills exactly one chunk mixes its 256-bit length in."""
    bl = Bitlist256(data=_bools(*([1] * 256)))
    expected_root = h(b"\xff" * 32, pad((256).to_bytes(32, "little")))
    assert hash_tree_root(bl) == expected_root


def test_hash_tree_root_bitlist_two_chunks() -> None:
    """A bitlist whose data spans two chunks merkleizes them and mixes in 512."""
    bl = Bitlist512(data=_bools(*([1] * 512)))
    base = h(b"\xff" * 32, b"\xff" * 32)
    expected_root = h(base, pad((512).to_bytes(32, "little")))
    assert hash_tree_root(bl) == expected_root


def test_hash_tree_root_vector_basic_single_chunk() -> None:
    """A vector of two Uint16 fits in one chunk; the root is the padded payload."""
    vector = Uint16Vector2(data=[Uint16(0x4567), Uint16(0x0123)])
    assert hash_tree_root(vector) == pad(b"\x67\x45\x23\x01")


def test_hash_tree_root_vector_basic_chunk_boundary() -> None:
    """A vector of sixteen Uint16 fills exactly one 32-byte chunk."""
    vector = Uint16Vector16(data=[Uint16(i) for i in range(16)])
    packed_bytes = b"".join(i.to_bytes(2, "little") for i in range(16))
    assert hash_tree_root(vector) == Bytes32(packed_bytes)


def test_hash_tree_root_vector_single_element() -> None:
    """A one-element vector of Uint16 yields the padded little-endian element."""
    vector = Uint16Vector1(data=[Uint16(0xABCD)])
    assert hash_tree_root(vector) == pad(b"\xcd\xab")


def test_hash_tree_root_vector_composite_elements() -> None:
    """A vector of three Bytes32 leaves merkleizes its element roots padded to width four."""
    leaf_a = Bytes32(b"\xbb\xaa" + b"\x00" * 30)
    leaf_b = Bytes32(b"\xad\xc0" + b"\x00" * 30)
    leaf_c = Bytes32(b"\xff\xee" + b"\x00" * 30)
    vector = Bytes32Vector3(data=[leaf_a, leaf_b, leaf_c])
    assert hash_tree_root(vector) == h(h(leaf_a, leaf_b), h(leaf_c, Z[0]))


def test_hash_tree_root_list_basic_small_limit() -> None:
    """A list of three Uint16 with capacity for 32 elements packs into a two-chunk tree."""
    test_list = Uint16List32(data=[Uint16(0xAABB), Uint16(0xC0AD), Uint16(0xEEFF)])
    base = h(pad(b"\xbb\xaa\xad\xc0\xff\xee"), Z[0])
    expected_root = h(base, pad(b"\x03"))
    assert hash_tree_root(test_list) == expected_root


def test_hash_tree_root_list_basic_large_limit() -> None:
    """A list of three Uint32 with capacity 128 pads up four levels then mixes in the length."""
    test_list = Uint32List128(data=[Uint32(0xAABB), Uint32(0xC0AD), Uint32(0xEEFF)])
    base = merge(pad(b"\xbb\xaa\x00\x00\xad\xc0\x00\x00\xff\xee\x00\x00"), Z[0:4])
    expected_root = h(base, pad(b"\x03"))
    assert hash_tree_root(test_list) == expected_root


def test_hash_tree_root_list_basic_empty() -> None:
    """An empty list with a large capacity uses the all-zero subtree at the capacity depth."""
    test_list = Uint32List128(data=[])
    expected_root = h(Z[4], pad(b"\x00"))
    assert hash_tree_root(test_list) == expected_root


def test_hash_tree_root_list_composite_elements() -> None:
    """A list of three Bytes32 elements merkleizes leaves to capacity depth then mixes length."""
    leaf_a = Bytes32(b"\xbb\xaa" + b"\x00" * 30)
    leaf_b = Bytes32(b"\xad\xc0" + b"\x00" * 30)
    leaf_c = Bytes32(b"\xff\xee" + b"\x00" * 30)
    test_list = Bytes32List32(data=[leaf_a, leaf_b, leaf_c])
    base = h(h(leaf_a, leaf_b), h(leaf_c, Z[0]))
    merkle = merge(base, Z[2:5])
    expected_root = h(merkle, pad(b"\x03"))
    assert hash_tree_root(test_list) == expected_root


def test_hash_tree_root_container_empty() -> None:
    """A container with no fields hashes to the empty-input merkle root."""
    assert hash_tree_root(EmptyContainer()) == Z[0]


def test_hash_tree_root_container_single_field() -> None:
    """A container with one basic field hashes that field as its only leaf."""
    container = SingleField(A=Uint8(0xAB))
    assert hash_tree_root(container) == pad(b"\xab")


def test_hash_tree_root_container_two_fields() -> None:
    """A container with two basic fields hashes each as its own leaf."""
    container = Small(A=Uint16(0x4567), B=Uint16(0x0123))
    assert hash_tree_root(container) == h(pad(b"\x67\x45"), pad(b"\x23\x01"))


def test_hash_tree_root_container_three_fields_pads_to_four() -> None:
    """A three-field container pads its leaves with one zero chunk to width four."""
    container = Fixed(A=Uint8(0xAB), B=Uint64(0xAABBCCDDEEFF0011), C=Uint32(0x12345678))
    left = h(pad(b"\xab"), pad(b"\x11\x00\xff\xee\xdd\xcc\xbb\xaa"))
    right = h(pad(b"\x78\x56\x34\x12"), Z[0])
    assert hash_tree_root(container) == h(left, right)


def test_hash_tree_root_container_with_empty_list_field() -> None:
    """An empty variable-size field contributes its own zero-tree root with length zero."""
    container = Var(A=Uint16(0xABCD), B=Uint16List1024(data=()), C=Uint8(0xFF))
    expected_b = h(Z[6], pad(b"\x00"))
    left = h(pad(b"\xcd\xab"), expected_b)
    right = h(pad(b"\xff"), Z[0])
    assert hash_tree_root(container) == h(left, right)


def test_hash_tree_root_container_with_populated_list_field() -> None:
    """A populated variable-size field contributes its data root with the element count."""
    container = Var(
        A=Uint16(0xABCD),
        B=Uint16List1024(data=(Uint16(1), Uint16(2), Uint16(3))),
        C=Uint8(0xFF),
    )
    base = merge(pad(b"\x01\x00\x02\x00\x03\x00"), Z[0:6])
    expected_b = h(base, pad(b"\x03"))
    left = h(pad(b"\xcd\xab"), expected_b)
    right = h(pad(b"\xff"), Z[0])
    assert hash_tree_root(container) == h(left, right)


def test_hash_tree_root_vector_of_composite_containers() -> None:
    """A fixed-length vector of containers hashes the per-element roots into a balanced tree."""

    def fixed_root(a: bytes, b: bytes, c: bytes) -> Bytes32:
        return h(h(pad(a), pad(b)), h(pad(c), Z[0]))

    fixed_vector = FixedVector4(
        data=[
            Fixed(A=Uint8(0xCC), B=Uint64(0x4242424242424242), C=Uint32(0x13371337)),
            Fixed(A=Uint8(0xDD), B=Uint64(0x3333333333333333), C=Uint32(0xABCDABCD)),
            Fixed(A=Uint8(0xEE), B=Uint64(0x4444444444444444), C=Uint32(0x00112233)),
            Fixed(A=Uint8(0xFF), B=Uint64(0x5555555555555555), C=Uint32(0x44556677)),
        ]
    )
    element_root_0 = fixed_root(b"\xcc", b"\x42" * 8, b"\x37\x13\x37\x13")
    element_root_1 = fixed_root(b"\xdd", b"\x33" * 8, b"\xcd\xab\xcd\xab")
    element_root_2 = fixed_root(b"\xee", b"\x44" * 8, b"\x33\x22\x11\x00")
    element_root_3 = fixed_root(b"\xff", b"\x55" * 8, b"\x77\x66\x55\x44")
    assert hash_tree_root(fixed_vector) == h(
        h(element_root_0, element_root_1), h(element_root_2, element_root_3)
    )


def test_hash_tree_root_vector_of_variable_containers() -> None:
    """A vector of variable-size containers still hashes the per-element roots."""

    def var_root(a: bytes, payload: bytes, count: int, c: bytes) -> Bytes32:
        base = merge(pad(payload), Z[0:6])
        b_root = h(base, pad(count.to_bytes(32, "little")))
        return h(h(pad(a), b_root), h(pad(c), Z[0]))

    variable_vector = VarVector2(
        data=[
            Var(
                A=Uint16(0xDEAD),
                B=Uint16List1024(data=(Uint16(1), Uint16(2), Uint16(3))),
                C=Uint8(0x11),
            ),
            Var(
                A=Uint16(0xBEEF),
                B=Uint16List1024(data=(Uint16(4), Uint16(5), Uint16(6))),
                C=Uint8(0x22),
            ),
        ]
    )
    element_root_0 = var_root(b"\xad\xde", b"\x01\x00\x02\x00\x03\x00", 3, b"\x11")
    element_root_1 = var_root(b"\xef\xbe", b"\x04\x00\x05\x00\x06\x00", 3, b"\x22")
    assert hash_tree_root(variable_vector) == h(element_root_0, element_root_1)


@pytest.mark.parametrize(
    "unsupported_value",
    [
        42,
        "hello",
        [1, 2, 3],
        {"k": 1},
        (1, 2),
        3.14,
        None,
    ],
    ids=["int", "str", "list", "dict", "tuple", "float", "none"],
)
def test_hash_tree_root_unsupported_type_raises(unsupported_value: object) -> None:
    """The dispatch fallback rejects values without a registered handler."""
    with pytest.raises(TypeError) as exception_info:
        hash_tree_root(unsupported_value)
    assert str(exception_info.value) == (
        f"hash_tree_root: unsupported value type {type(unsupported_value).__name__}"
    )


def test_hash_tree_root_is_deterministic() -> None:
    """Repeated calls on equal inputs return byte-identical roots."""
    first_list = Uint16List1024(data=(Uint16(1), Uint16(2), Uint16(3)))
    second_list = Uint16List1024(data=(Uint16(1), Uint16(2), Uint16(3)))
    assert hash_tree_root(first_list) == hash_tree_root(second_list)


def test_hash_tree_root_distinguishes_by_length() -> None:
    """Variable-length types with the same data but different lengths produce different roots."""
    short_list = Uint16List1024(data=(Uint16(1), Uint16(2)))
    long_list = Uint16List1024(data=(Uint16(1), Uint16(2), Uint16(0)))
    assert hash_tree_root(short_list) != hash_tree_root(long_list)
