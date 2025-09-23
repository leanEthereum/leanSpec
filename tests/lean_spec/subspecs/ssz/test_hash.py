""" "SSZ hash tree root tests."""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Iterable, Tuple, Type

import pytest

from lean_spec.subspecs.ssz.hash import HashTreeRoot, hash_tree_root
from lean_spec.types.bitfields import Bitlist, Bitvector
from lean_spec.types.boolean import Boolean
from lean_spec.types.byte import Byte
from lean_spec.types.byte_arrays import BaseBytes, ByteListBase, Bytes48
from lean_spec.types.collections import SSZList, SSZVector
from lean_spec.types.container import Container
from lean_spec.types.ssz_base import SSZType
from lean_spec.types.uint import (
    BaseUint,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint256,
)
from lean_spec.types.union import Union


# Concrete SSZList classes for tests
class Uint16List32(SSZList):
    ELEMENT_TYPE = Uint16
    LIMIT = 32


class Uint16List128(SSZList):
    ELEMENT_TYPE = Uint16
    LIMIT = 128


class Uint16List1024(SSZList):
    ELEMENT_TYPE = Uint16
    LIMIT = 1024


class Uint32List128(SSZList):
    ELEMENT_TYPE = Uint32
    LIMIT = 128


class Uint256List32(SSZList):
    ELEMENT_TYPE = Uint256
    LIMIT = 32


def _le_hex(value: int, byte_len: int) -> str:
    """
    Converts an integer to a little-endian hexadecimal string of a fixed length.

    Args:
        value: The integer to convert.
        byte_len: The exact number of bytes the output hex string should represent.

    Returns:
        A hexadecimal string representation of the integer.
    """
    return value.to_bytes(byte_len, "little").hex()


def chunk(payload_hex: str) -> str:
    """
    Pads or truncates a hexadecimal string to form a 32-byte chunk.

    According to SSZ, data is processed in 32-byte chunks. This function
    ensures that any given hex string is correctly formatted as a 32-byte
    (64-character) hex string by right-padding with '00' or truncating if necessary.

    Args:
        payload_hex: The input hexadecimal string.

    Returns:
        A 64-character hexadecimal string representing a 32-byte chunk.
    """
    return (payload_hex + ("00" * 32))[:64]


def h(a_hex: str, b_hex: str) -> str:
    """
    Computes the SHA-256 hash of the concatenation of two 32-byte hex chunks.

    This is the core Merkle tree hashing operation, combining two child nodes
    to form a parent node.

    Args:
        a_hex: The left 32-byte chunk as a hex string.
        b_hex: The right 32-byte chunk as a hex string.

    Returns:
        The resulting 32-byte SHA-256 hash as a hex string.
    """
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)
    return sha256(a + b).hexdigest()


# Precompute the "zero hashes" used for padding Merkle trees.
#
# ZERO_HASHES[i] is the hash of two ZERO_HASHES[i-1] nodes, forming a
# balanced Merkle subtree of zero chunks at increasing depths.
ZERO_HASHES = [chunk("")]
for _ in range(1, 32):
    ZERO_HASHES.append(h(ZERO_HASHES[-1], ZERO_HASHES[-1]))


def merge(leaf: str, branch: Iterable[str]) -> str:
    """
    Merges a leaf with a branch of nodes in a Merkle tree structure.

    This helper simulates the process of hashing a leaf up a series of parent
    nodes in a Merkle proof, combining the current hash with a sibling node at
    each level.

    Args:
        leaf: The initial leaf hash as a hex string.
        branch: An iterable of sibling node hashes to merge with.

    Returns:
        The final root hash after merging the leaf all the way up the branch.
    """
    out = leaf
    for b in branch:
        out = h(out, b)
    return out


def _chunk_hex(payload_hex: str) -> str:
    """
    Alias for the `chunk` function for semantic clarity in tests.
    """
    return chunk(payload_hex)


@pytest.mark.parametrize(
    "uint_type,value_int,le_hex",
    [
        # uint8
        (Uint8, 0x00, _le_hex(0x00, 1)),
        (Uint8, 0x01, _le_hex(0x01, 1)),
        (Uint8, 0xAB, _le_hex(0xAB, 1)),
        # uint16
        (Uint16, 0x0000, _le_hex(0x0000, 2)),
        (Uint16, 0xABCD, _le_hex(0xABCD, 2)),
        # uint32
        (Uint32, 0x00000000, _le_hex(0x00000000, 4)),
        (Uint32, 0x01234567, _le_hex(0x01234567, 4)),
        # uint64
        (Uint64, 0x0000000000000000, _le_hex(0x0000000000000000, 8)),
        (Uint64, 0x0123456789ABCDEF, _le_hex(0x0123456789ABCDEF, 8)),
        # uint128
        (Uint128, 0x0, _le_hex(0x0, 16)),
        (
            Uint128,
            0x11223344556677880123456789ABCDEF,
            _le_hex(0x11223344556677880123456789ABCDEF, 16),
        ),
        # uint256
        (Uint256, 0x0, _le_hex(0x0, 32)),
    ],
)
def test_hash_tree_root_uints(uint_type: Type[BaseUint], value_int: int, le_hex: str) -> None:
    """
    Tests the hash tree root of various unsigned integer types (Uint).

    For basic types like integers, the hash tree root is simply their
    little-endian byte representation, right-padded with zeros to 32 bytes.

    This test covers integers of different bit lengths.
    """
    # Instantiate the specific SSZ integer type with the test value.
    val = uint_type(value_int)
    # Calculate the hash tree root using both the functional and object-oriented approaches.
    root_fn = hash_tree_root(val)
    root_oo = HashTreeRoot.compute(val)
    # The expected root is the little-endian hex string padded to a 32-byte chunk.
    expected_chunk = _chunk_hex(le_hex)
    # Verify that both calculated roots match the expected chunk.
    assert root_fn.hex() == expected_chunk
    assert root_oo.hex() == expected_chunk
    # Ensure both calculation methods produce the exact same result.
    assert root_fn == root_oo


@pytest.mark.parametrize(
    "val, serialized_hex",
    [
        (Boolean(False), "00"),
        (Boolean(True), "01"),
    ],
)
def test_hash_tree_root_boolean(val: Boolean, serialized_hex: str) -> None:
    """
    Tests the hash tree root of the Boolean type.

    A boolean is serialized as `0x01` for True and `0x00` for False.

    Its hash tree root is this single byte, right-padded to 32 bytes.
    """
    # The expected root is the boolean's serialized hex byte ('00' or '01') padded to 32 bytes.
    expected = chunk(serialized_hex)
    # Verify the functional approach gives the correct root.
    assert hash_tree_root(val).hex() == expected
    # Verify the object-oriented approach gives the correct root.
    assert HashTreeRoot.compute(val).hex() == expected


@pytest.mark.parametrize(
    "payload_hex",
    [
        "",  # Empty bytes
        "00",  # Single byte
        "01",
        "ab",
        "00010203",  # Multiple bytes
        "ff" * 31,  # 31 bytes, requires padding
        "ff" * 32,  # Exactly one chunk
        "ff" * 33,  # More than one chunk, requires Merklization
    ],
)
def test_hash_tree_root_raw_bytes_like(payload_hex: str) -> None:
    """Tests that `hash_tree_root` handles various raw byte-like inputs consistently."""
    # Convert the hex payload to a bytes object.
    data = bytes.fromhex(payload_hex)

    # Compute the hash tree root for `bytes`.
    got_b = hash_tree_root(data).hex()
    # Compute the hash tree root for `bytearray`.
    got_ba = hash_tree_root(bytearray(data)).hex()
    # Compute the hash tree root for `memoryview`.
    got_mv = hash_tree_root(memoryview(data)).hex()

    # The core SSZ logic is to pack the data into chunks and then Merkleize.
    # - For a single chunk or less, the root is just the padded chunk.
    # - For multiple chunks, it's the root of the Merkle tree.
    #
    # This assertion verifies that all byte-like input types are treated identically.
    assert got_b == got_ba == got_mv


def test_hash_tree_root_bytevector_48() -> None:
    """Tests the hash tree root of a fixed-size `ByteVector` that spans multiple chunks."""
    # Create a ByteVector of 48 bytes with values 0x00 to 0x2F (47).
    bv = Bytes48(bytes(range(48)))
    # Define the first 32-byte chunk (bytes 0-31).
    left = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    # Define the second chunk (bytes 32-47), right-padded with zeros to 32 bytes.
    right = "202122232425262728292a2b2c2d2e2f00000000000000000000000000000000"
    # The expected root is the hash of the two chunks.
    expected = h(left, right)
    # Verify the calculated root matches the expected hash.
    assert hash_tree_root(bv).hex() == expected


def test_hash_tree_root_bytelist_small_empty() -> None:
    """
    Tests the hash tree root of an empty, small-capacity `ByteList`.

    For a list, the root is a mix-in of the Merkle root of the data and the list's
    length. For an empty list with a capacity of 10 bytes (which fits in one
    chunk), the data root is a single zero chunk. This is then hashed with the
    list's length (0) to get the final root.
    """
    # Create an empty ByteList with a capacity of 10 bytes.
    bl = ByteList10(data=b"")
    # The data root for an empty list within a single-chunk capacity is the zero chunk.
    # - The length (0) is serialized and chunked.
    # - The final root is hash(zero_chunk, chunk(length)).
    expected = h(chunk(""), chunk("00"))
    # Verify the calculated root.
    assert hash_tree_root(bl).hex() == expected


def test_hash_tree_root_bytelist_big_empty() -> None:
    """
    Tests the hash tree root of an empty, large-capacity `ByteList`.

    If the list's capacity (2048 bytes = 64 chunks) requires a non-trivial Merkle
    tree, the data root for an empty list is the root of a balanced tree of zero
    chunks. For 64 chunks, this is `ZERO_HASHES[6]`. This root is then mixed in
    with the length (0).
    """
    # Create an empty ByteList with a capacity of 2048 bytes.
    bl = ByteList2048(data=b"")
    # The data root for a 64-chunk capacity is the precomputed zero hash at depth 6.
    # This is then hashed with the length (0).
    expected = h(ZERO_HASHES[6], chunk("00"))
    # Verify the calculated root.
    assert hash_tree_root(bl).hex() == expected


@pytest.mark.parametrize(
    "limit, payload_hex, expected_root_hex",
    [
        # Case 1: 7-byte list. Fits in one chunk. Root is hash(chunk(data), chunk(length=7)).
        (7, "00010203040506", h(chunk("00010203040506"), chunk("07"))),
        # Case 2: 50-byte list. Spans two chunks. Merkleize data chunks, then mix in length.
        (
            50,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031",
            h(
                h(
                    # Chunk 1
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    # Chunk 2 (padded)
                    "202122232425262728292a2b2c2d2e2f30310000000000000000000000000000",
                ),
                chunk("32"),  # Length is 50 (0x32)
            ),
        ),
        # Case 3: 256-byte limit, but only 6 bytes of data.
        # Data root requires padding up to the capacity's Merkle tree depth.
        # 256 bytes = 8 chunks, depth = 3.
        (
            256,
            "000102030405",
            h(
                # Merkleize the single data chunk with zero hashes to a depth of 3.
                h(h(h(chunk("000102030405"), ZERO_HASHES[0]), ZERO_HASHES[1]), ZERO_HASHES[2]),
                # Mix in the length (6).
                chunk("06"),
            ),
        ),
    ],
)
def test_hash_tree_root_bytelist_various(
    limit: int, payload_hex: str, expected_root_hex: str
) -> None:
    """
    Tests `ByteList` hash tree root calculation for various sizes and capacities.
    """
    # Create the ByteList instance for the current test case.
    # Map limit values to explicit ByteList classes
    bytelist_classes = {
        7: ByteList7,
        50: ByteList50,
        256: ByteList256,
    }
    bytelist_class = bytelist_classes[limit]
    bl = bytelist_class(data=bytes.fromhex(payload_hex))
    # Verify the calculated root matches the pre-computed expected root.
    assert hash_tree_root(bl).hex() == expected_root_hex


@pytest.mark.parametrize(
    "bits, expect_serial_hex, expect_root_hex",
    [
        # Bitvector[8]: 8 bits fit in 1 byte. Root is the chunk of that byte.
        ((1, 1, 0, 1, 0, 1, 0, 0), "2b", chunk("2b")),
        # Bitvector[4]: 4 bits fit in 1 byte.
        ((0, 1, 0, 1), "0a", chunk("0a")),
        # Bitvector[3]: 3 bits fit in 1 byte.
        ((0, 1, 0), "02", chunk("02")),
    ],
)
def test_hash_tree_root_bitvector(
    bits: Tuple[int, ...], expect_serial_hex: str, expect_root_hex: str
) -> None:
    """
    Tests the hash tree root of `Bitvector` (fixed-size bitfield).

    A `Bitvector` is serialized into the minimum number of bytes required.
    Its hash tree root is the Merkle root of these bytes, treated like a `ByteVector`.
    """
    # Create the Bitvector instance.
    bv = Bitvector[len(bits)](bits)
    # Sanity check: ensure the serialization is correct.
    assert bv.encode_bytes().hex() == expect_serial_hex
    # Verify the hash tree root.
    assert hash_tree_root(bv).hex() == expect_root_hex


@pytest.mark.parametrize(
    "limit, bits, expect_serial_hex, expect_root_hex",
    [
        # Bitlist[8]: 8 bits + length bit serialize to 2 bytes ("2b01").
        # The data root is chunk("2b"), mixed with length 8.
        (8, (1, 1, 0, 1, 0, 1, 0, 0), "2b01", h(chunk("2b"), chunk("08"))),
        # Bitlist[4]: 4 bits + length bit serialize to 1 byte ("1a").
        # The data part is "0a". The root is hash(chunk("0a"), chunk(length=4)).
        (4, (0, 1, 0, 1), "1a", h(chunk("0a"), chunk("04"))),
        # Bitlist[3]: 3 bits + length bit serialize to 1 byte ("0a").
        # Data part is "02". Root is hash(chunk("02"), chunk(length=3)).
        (3, (0, 1, 0), "0a", h(chunk("02"), chunk("03"))),
    ],
)
def test_hash_tree_root_bitlist(
    limit: int, bits: Tuple[int, ...], expect_serial_hex: str, expect_root_hex: str
) -> None:
    """
    Tests the hash tree root of `Bitlist` (variable-size bitfield).

    A `Bitlist`'s serialization includes a "length bit". The hash tree root
    calculation separates the data bits from the length, Merkleizes the data
    part, and then mixes in the number of bits.
    """
    # Create the Bitlist instance.
    bl = Bitlist[limit](bits)
    # Sanity check the SSZ serialization.
    assert bl.encode_bytes().hex() == expect_serial_hex
    # Verify the hash tree root.
    assert hash_tree_root(bl).hex() == expect_root_hex


def test_hash_tree_root_bitvector_512_all_ones() -> None:
    """
    Tests the hash tree root of a large `Bitvector` that spans multiple chunks.
    """
    # A 512-bit vector is 64 bytes, which is exactly two 32-byte chunks.
    bv = Bitvector[512]((1,) * 512)
    # Both chunks will be all `0xff` bytes.
    left = "ff" * 32
    right = "ff" * 32
    # The root is the hash of these two chunks.
    expected = h(left, right)
    # Verify the result.
    assert hash_tree_root(bv).hex() == expected


def test_hash_tree_root_bitlist_512_all_ones() -> None:
    """
    Tests the hash tree root of a large `Bitlist`.
    """
    # Create a Bitlist of 512 bits.
    bl = Bitlist[512]((1,) * 512)
    # The data part is 512 bits (64 bytes), which forms two full chunks of `0xff`.
    # The Merkle root of the data is the hash of these two chunks.
    base = h("ff" * 32, "ff" * 32)
    # This data root is then hashed with the list's length (512).
    # 512 in little-endian is `0x0002`, which is hex "0002".
    expected = h(base, chunk("0002"))
    # Verify the result.
    assert hash_tree_root(bl).hex() == expected


# Define explicit SSZVector types for testing our new approach
class Uint16Vector2(SSZVector):
    """A vector of exactly 2 Uint16 values."""

    ELEMENT_TYPE = Uint16
    LENGTH = 2


# Forward declare classes for Complex container test
class FixedVector4(SSZVector):
    """A vector of exactly 4 Fixed values."""

    ELEMENT_TYPE = None  # type: ignore[assignment] # Will be set after Fixed is defined
    LENGTH = 4


class VarVector2(SSZVector):
    """A vector of exactly 2 Var values."""

    ELEMENT_TYPE = None  # type: ignore[assignment] # Will be set after Var is defined
    LENGTH = 2


def test_hash_tree_root_vector_uint16_2() -> None:
    """
    Tests the hash tree root of an `SSZVector` of basic types.

    If the total serialized size of an SSZVector is <= 32 bytes, the root is
    simply the serialized bytes, right-padded to 32 bytes.
    """
    # SSZVector of two Uint16 values - using our new explicit class definition
    v = Uint16Vector2(data=[0x4567, 0x0123])
    # Serialization (little-endian): 0x4567 -> "6745", 0x0123 -> "2301".
    # Concatenated: "67452301". This is 4 bytes, which fits in one chunk.
    expected = chunk("67452301")
    # Verify the root is the padded serialization.
    assert hash_tree_root(v).hex() == expected


def test_hash_tree_root_list_uint16() -> None:
    """
    Tests the hash tree root of a `List` of basic types.
    """
    # Create a list of three Uint16 elements.
    test_list = Uint16List32(data=(0xAABB, 0xC0AD, 0xEEFF))
    # The serialized data is "bbaaadc0ffee" (3 * 2 = 6 bytes).
    # The capacity is 32 * 2 = 64 bytes = 2 chunks.
    # The data is packed into chunks and Merkleized. Here, it's one data chunk and one zero chunk.
    base = h(chunk("bbaaadc0ffee"), chunk(""))
    # This data root is mixed in with the element count (3).
    expected = h(base, chunk("03"))
    # Verify the result.
    assert hash_tree_root(test_list).hex() == expected


def test_hash_tree_root_list_uint32_large_limit() -> None:
    """
    Tests a `List` of basic types with a large capacity, requiring padding.
    """
    # List of three Uint32s, capacity 128 elements.
    test_list = Uint32List128(data=(0xAABB, 0xC0AD, 0xEEFF))
    # Capacity: 128 * 4 = 512 bytes = 16 chunks. Tree depth is 4 (2^4=16).
    # Serialized data: "bbaa0000adc00000ffee0000" (3 * 4 = 12 bytes), fits in one chunk.
    # This single chunk must be Merkleized with zero hashes up to depth 4.
    base = merge(chunk("bbaa0000adc00000ffee0000"), ZERO_HASHES[0:4])
    # Finally, mix in the element count (3).
    expected = h(base, chunk("03"))
    # Verify the result.
    assert hash_tree_root(test_list).hex() == expected


def test_hash_tree_root_list_uint256() -> None:
    """
    Tests a `List` where each element is itself a 32-byte chunk.
    """
    # Create a list of three Uint256 elements.
    test_list = Uint256List32(data=(0xAABB, 0xC0AD, 0xEEFF))
    # Each Uint256 is a 32-byte leaf. We have 3 leaves.
    a = chunk("bbaa")  # 0xAABB
    b = chunk("adc0")  # 0xC0AD
    c = chunk("ffee")  # 0xEEFF
    # Merkleize the three leaves, padding to 4 with a zero chunk.
    base = h(h(a, b), h(c, chunk("")))
    # The list capacity is 32 elements, so the tree depth is 5 (2^5=32).
    # We already have a root for 4 leaves (depth 2), so merge with zero hashes from depth 2 to 5.
    merkle = merge(base, ZERO_HASHES[2:5])
    # Mix in the element count (3).
    expected = h(merkle, chunk("03"))
    # Verify the result.
    assert hash_tree_root(test_list).hex() == expected


# Define explicit ByteVector and ByteList types for testing.
# Using existing Bytes48 class instead of custom ByteVector48
# class ByteVector48(BaseBytes):
#     """A fixed-size byte vector of exactly 48 bytes."""
#     LENGTH = 48


class ByteList10(ByteListBase):
    """A variable-size byte list with a maximum of 10 bytes."""

    LIMIT = 10

    @classmethod
    def get_byte_length(cls) -> int:
        """ByteList is variable-size, so this raises a TypeError."""
        raise TypeError(f"{cls.__name__} is variable-size")


class ByteList7(ByteListBase):
    """A variable-size byte list with a maximum of 7 bytes."""

    LIMIT = 7

    @classmethod
    def get_byte_length(cls) -> int:
        """ByteList is variable-size, so this raises a TypeError."""
        raise TypeError(f"{cls.__name__} is variable-size")


class ByteList50(ByteListBase):
    """A variable-size byte list with a maximum of 50 bytes."""

    LIMIT = 50

    @classmethod
    def get_byte_length(cls) -> int:
        """ByteList is variable-size, so this raises a TypeError."""
        raise TypeError(f"{cls.__name__} is variable-size")


class ByteList256(ByteListBase):
    """A variable-size byte list with a maximum of 256 bytes."""

    LIMIT = 256

    @classmethod
    def get_byte_length(cls) -> int:
        """ByteList is variable-size, so this raises a TypeError."""
        raise TypeError(f"{cls.__name__} is variable-size")


class ByteList2048(ByteListBase):
    """A variable-size byte list with a maximum of 2048 bytes."""

    LIMIT = 2048

    @classmethod
    def get_byte_length(cls) -> int:
        """ByteList is variable-size, so this raises a TypeError."""
        raise TypeError(f"{cls.__name__} is variable-size")


# Define explicit Union types for testing.
class UnionUint16(SSZType):
    """A union type that can hold Uint16."""

    OPTIONS = (Uint16,)

    def __init__(self, selector: int, value: Any):
        # This is a simplified implementation for testing
        self.selector = selector
        self.value = value

    @classmethod
    def is_fixed_size(cls) -> bool:
        """Union is variable-size."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """Union is variable-size, so this raises a TypeError."""
        raise TypeError(f"{cls.__name__} is variable-size")

    def serialize(self, stream: Any) -> int:
        """Simplified serialize for testing."""
        raise NotImplementedError("Not implemented for test")

    @classmethod
    def deserialize(cls, stream: Any, scope: int) -> Any:
        """Simplified deserialize for testing."""
        raise NotImplementedError("Not implemented for test")


class UnionNoneUint16Uint32(SSZType):
    """A union type that can hold None, Uint16, or Uint32."""

    OPTIONS = (None, Uint16, Uint32)

    def __init__(self, selector: int, value: Any):
        self.selector = selector
        self.value = value

    @classmethod
    def is_fixed_size(cls) -> bool:
        """Union is variable-size."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """Union is variable-size, so this raises a TypeError."""
        raise TypeError(f"{cls.__name__} is variable-size")

    def serialize(self, stream: Any) -> int:
        """Simplified serialize for testing."""
        raise NotImplementedError("Not implemented for test")

    @classmethod
    def deserialize(cls, stream: Any, scope: int) -> Any:
        """Simplified deserialize for testing."""
        raise NotImplementedError("Not implemented for test")


class UnionUint16Uint32(SSZType):
    """A union type that can hold Uint16 or Uint32."""

    OPTIONS = (Uint16, Uint32)

    def __init__(self, selector: int, value: Any):
        self.selector = selector
        self.value = value

    @classmethod
    def is_fixed_size(cls) -> bool:
        """Union is variable-size."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """Union is variable-size, so this raises a TypeError."""
        raise TypeError(f"{cls.__name__} is variable-size")

    def serialize(self, stream: Any) -> int:
        """Simplified serialize for testing."""
        raise NotImplementedError("Not implemented for test")

    @classmethod
    def deserialize(cls, stream: Any, scope: int) -> Any:
        """Simplified deserialize for testing."""
        raise NotImplementedError("Not implemented for test")


# Define SSZ Container types for testing.
class SingleField(Container):
    A: Byte


class Small(Container):
    A: Uint16
    B: Uint16


class Fixed(Container):
    A: Uint8
    B: Uint64
    C: Uint32


class Var(Container):
    A: Uint16
    B: Uint16List1024
    C: Uint8


# Set the ELEMENT_TYPE now that the classes are defined
FixedVector4.ELEMENT_TYPE = Fixed  # type: ignore[has-type]
VarVector2.ELEMENT_TYPE = Var  # type: ignore[has-type]


class Complex(Container):
    A: Uint16
    B: Uint16List128
    C: Uint8
    D: ByteList256
    E: Var
    F: FixedVector4
    G: VarVector2


def test_hash_tree_root_container_singlefield() -> None:
    """
    Tests the hash tree root of a container with a single basic field.
    """
    # For a container with one basic field, the root is just the chunk of that field.
    v = SingleField(A=Byte(0xAB))
    expected = chunk("ab")
    assert hash_tree_root(v).hex() == expected


def test_hash_tree_root_container_small() -> None:
    """
    Tests a container with two basic fields that fit within one chunk.
    """
    # Create a container with two Uint16 fields.
    v = Small(A=Uint16(0x4567), B=Uint16(0x0123))
    # The fields are chunked separately and then hashed.
    # Note: SSZ chunks fields, not their concatenated serialization.
    expected = h(chunk("6745"), chunk("2301"))
    assert hash_tree_root(v).hex() == expected


def test_hash_tree_root_container_fixed() -> None:
    """
    Tests a container with multiple fixed-size fields, requiring Merklization.
    """
    # Create the container instance.
    v = Fixed(A=Uint8(0xAB), B=Uint64(0xAABBCCDDEEFF0011), C=Uint32(0x12345678))
    # The fields A, B, C are chunked. Since there are 3 fields, the tree is padded to 4.
    # Tree structure: h( h(chunk(A), chunk(B)), h(chunk(C), zero_chunk) )
    expected = h(h(chunk("ab"), chunk("1100ffeeddccbbaa")), h(chunk("78563412"), chunk("")))
    assert hash_tree_root(v).hex() == expected


def test_hash_tree_root_container_var_empty() -> None:
    """
    Tests a container with a variable-size list that is empty.
    """
    # Create a container where field B is an empty List.
    v = Var(A=Uint16(0xABCD), B=Uint16List1024(data=()), C=Uint8(0xFF))
    # The root of the empty list B is calculated first.
    # Capacity 1024*2 bytes = 64 chunks, so empty root is ZERO_HASHES[6].
    # This is mixed with length 0.
    expected_b = h(ZERO_HASHES[6], chunk("00000000"))  # Length for basic lists is uint64
    # The container's fields are then Merkleized.
    expected = h(h(chunk("cdab"), expected_b), h(chunk("ff"), chunk("")))
    assert hash_tree_root(v).hex() == expected


def test_hash_tree_root_container_var_some() -> None:
    """
    Tests a container with a populated variable-size list.
    """
    # Create a container with a list containing three elements.
    v = Var(A=Uint16(0xABCD), B=Uint16List1024(data=(1, 2, 3)), C=Uint8(0xFF))
    # Calculate the root of list B.
    # Data "010002000300" is padded to capacity (64 chunks, depth 6).
    base = merge(chunk("010002000300"), ZERO_HASHES[0:6])
    # Mix in the length (3).
    expected_b = h(base, chunk("03"))
    # Merkleize the container fields' roots.
    expected = h(h(chunk("cdab"), expected_b), h(chunk("ff"), chunk("")))
    assert hash_tree_root(v).hex() == expected


def test_hash_tree_root_container_complex() -> None:
    """
    Tests a complex, nested container with all types of fields.
    """
    # Instantiate the deeply nested container.
    v = Complex(
        A=Uint16(0xAABB),
        B=Uint16List128(data=(0x1122, 0x3344)),
        C=Uint8(0xFF),
        D=ByteList256(data=b"foobar"),
        E=Var(A=Uint16(0xABCD), B=Uint16List1024(data=(1, 2, 3)), C=Uint8(0xFF)),
        F=FixedVector4(
            data=[
                Fixed(A=Uint8(0xCC), B=Uint64(0x4242424242424242), C=Uint32(0x13371337)),
                Fixed(A=Uint8(0xDD), B=Uint64(0x3333333333333333), C=Uint32(0xABCDABCD)),
                Fixed(A=Uint8(0xEE), B=Uint64(0x4444444444444444), C=Uint32(0x00112233)),
                Fixed(A=Uint8(0xFF), B=Uint64(0x5555555555555555), C=Uint32(0x44556677)),
            ]
        ),
        G=VarVector2(
            data=[
                Var(A=Uint16(0xDEAD), B=Uint16List1024(data=(1, 2, 3)), C=Uint8(0x11)),
                Var(A=Uint16(0xBEEF), B=Uint16List1024(data=(4, 5, 6)), C=Uint8(0x22)),
            ]
        ),
    )

    # Manually build the expected root by calculating the root of each field
    # and then Merkleizing them together, mirroring the container structure.

    # Root of field B: List[Uint16, 128]
    b_base = merge(chunk("22114433"), ZERO_HASHES[0:3])
    b_root = h(b_base, chunk("02"))

    # Root of field D: ByteList[256]
    d_base = merge(chunk("666f6f626172"), ZERO_HASHES[0:3])
    d_root = h(d_base, chunk("06"))

    # Root of field E: Var container
    e_data_base = merge(chunk("010002000300"), ZERO_HASHES[0:6])
    e_b_root = h(e_data_base, chunk("03"))
    e_root = h(h(chunk("cdab"), e_b_root), h(chunk("ff"), chunk("")))

    # Root of field F: FixedVector4
    def fixed_root(a: str, b: str, c: str) -> str:
        return h(h(chunk(a), chunk(b)), h(chunk(c), chunk("")))

    f_roots = [
        fixed_root("cc", "4242424242424242", "37133713"),
        fixed_root("dd", "3333333333333333", "cdabcdab"),
        fixed_root("ee", "4444444444444444", "33221100"),
        fixed_root("ff", "5555555555555555", "77665544"),
    ]
    f_root = h(h(f_roots[0], f_roots[1]), h(f_roots[2], f_roots[3]))

    # Root of field G: VarVector2
    def var_root(a_hex: str, payload_hex: str, count_hex: str, c_hex: str) -> str:
        b_base_local = merge(chunk(payload_hex), ZERO_HASHES[0:6])
        b_root_local = h(b_base_local, chunk(count_hex))
        return h(h(chunk(a_hex), b_root_local), h(chunk(c_hex), chunk("")))

    g0 = var_root("adde", "010002000300", "03", "11")
    g1 = var_root("efbe", "040005000600", "03", "22")
    g_root = h(g0, g1)

    # Final Merklization of all field roots (A, B, C, D, E, F, G), padded to 8 leaves.
    left = h(h(chunk("bbaa"), b_root), h(chunk("ff"), d_root))
    right = h(h(e_root, f_root), h(g_root, chunk("")))
    expected = h(left, right)

    # Verify the final calculated root.
    assert hash_tree_root(v).hex() == expected


@pytest.mark.skip(reason="Union implementation needs update for new type system")
def test_hash_tree_root_union_single_type() -> None:
    """
    Tests the hash tree root of a Union object.
    """
    # Define a Union type with one possible member.
    union = UnionUint16
    # Instantiate the union, selecting the first type (selector=0).
    u = union(selector=0, value=Uint16(0xAABB))
    # The root is hash(root(value), chunk(selector)).
    # For selector 0, this is hashed with a zero chunk.
    expected = h(chunk("bbaa"), chunk(""))
    assert hash_tree_root(u).hex() == expected


@pytest.mark.skip(reason="Union implementation needs update for new type system")
def test_hash_tree_root_union_with_none_arm() -> None:
    """
    Tests a Union where the selected type is `None`.
    """
    # Define a Union type that includes None.
    union = UnionNoneUint16Uint32
    # Instantiate with the None type (selector=0).
    u = union(selector=0, value=None)
    # For a `None` value, the value root is a zero chunk.
    # This is hashed with the selector (0), which is also a zero chunk.
    expected = h(chunk(""), chunk(""))
    assert hash_tree_root(u).hex() == expected


@pytest.mark.skip(reason="Union implementation needs update for new type system")
def test_hash_tree_root_union_other_arm() -> None:
    """
    Tests a Union where a non-zero selector is used.
    """
    # Define the Union type.
    union = UnionNoneUint16Uint32
    # Instantiate with the second type (selector=1).
    u = union(selector=1, value=Uint16(0xAABB))
    # The root is hash(root(value), chunk(selector=1)).
    expected = h(chunk("bbaa"), chunk("01"))
    assert hash_tree_root(u).hex() == expected


@pytest.mark.skip(reason="Union implementation needs update for new type system")
def test_hash_tree_root_union_multi_other_arm() -> None:
    """
    Tests a Union with multiple non-None types.
    """
    # Define a union of two integer types.
    union = UnionUint16Uint32
    # Instantiate with the second type (selector=1), which is Uint32.
    u = union(selector=1, value=Uint32(0xDEADBEEF))
    # The root is hash(root(value), chunk(selector=1)).
    expected = h(chunk("efbeadde"), chunk("01"))
    assert hash_tree_root(u).hex() == expected
