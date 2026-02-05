"""Tests for edge cases in SSZ serialization/deserialization."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types.bitfields import BaseBitlist, BaseBitvector
from lean_spec.types.boolean import Boolean
from lean_spec.types.byte_arrays import BaseByteList, Bytes32
from lean_spec.types.collections import SSZList, SSZVector
from lean_spec.types.container import Container
from lean_spec.types.uint import BaseUint, Uint8, Uint16, Uint32, Uint64

# Test type definitions


class Uint8Vector0(SSZVector[Uint8]):
    """Empty vector (edge case)."""

    LENGTH = 0


class Uint16Vector1(SSZVector[Uint16]):
    """Single-element vector."""

    LENGTH = 1


class Uint64Vector4(SSZVector[Uint64]):
    """Vector of 4 Uint64 values."""

    LENGTH = 4


class Uint8List8(SSZList[Uint8]):
    """List with small limit."""

    LIMIT = 8


class Uint64List1(SSZList[Uint64]):
    """Single-element max list."""

    LIMIT = 1


class Bitlist1(BaseBitlist):
    """Bitlist with limit of 1 bit."""

    LIMIT = 1


class Bitlist8(BaseBitlist):
    """Bitlist with limit of 8 bits."""

    LIMIT = 8


class Bitlist256(BaseBitlist):
    """Bitlist spanning multiple bytes."""

    LIMIT = 256


class Bitvector1(BaseBitvector):
    """Single-bit bitvector."""

    LENGTH = 1


class Bitvector7(BaseBitvector):
    """Non-byte-aligned bitvector."""

    LENGTH = 7


class Bitvector8(BaseBitvector):
    """Byte-aligned bitvector."""

    LENGTH = 8


class Bitvector9(BaseBitvector):
    """Bitvector spanning partial second byte."""

    LENGTH = 9


class ByteList1(BaseByteList):
    """Single-byte list."""

    LIMIT = 1


class EmptyContainer(Container):
    """Container with no fields."""

    pass


class SingleFieldContainer(Container):
    """Container with single field."""

    value: Uint64


class AllFixedContainer(Container):
    """Container with all fixed-size fields."""

    a: Uint8
    b: Uint16
    c: Uint32
    d: Uint64


# Empty collection tests


class TestEmptyCollections:
    """Tests for empty collections."""

    def test_empty_list_roundtrip(self) -> None:
        """Empty list serializes and deserializes correctly."""
        original = Uint8List8(data=[])

        encoded = original.encode_bytes()
        decoded = Uint8List8.decode_bytes(encoded)

        assert len(decoded) == 0
        assert encoded == b""

    def test_empty_bitlist_roundtrip(self) -> None:
        """Empty bitlist has just the delimiter byte."""
        original = Bitlist8(data=[])

        encoded = original.encode_bytes()
        decoded = Bitlist8.decode_bytes(encoded)

        assert len(decoded.data) == 0
        assert encoded == b"\x01"  # Just delimiter bit

    def test_empty_bytelist_roundtrip(self) -> None:
        """Empty bytelist roundtrips correctly."""
        original = ByteList1(data=b"")

        encoded = original.encode_bytes()
        decoded = ByteList1.decode_bytes(encoded)

        assert len(decoded.data) == 0

    def test_empty_container_roundtrip(self) -> None:
        """Empty container serializes to empty bytes."""
        original = EmptyContainer()

        encoded = original.encode_bytes()
        decoded = EmptyContainer.decode_bytes(encoded)

        assert encoded == b""
        assert isinstance(decoded, EmptyContainer)


# Single-element collection tests


class TestSingleElementCollections:
    """Tests for single-element collections."""

    def test_single_element_vector_roundtrip(self) -> None:
        """Single-element vector roundtrips correctly."""
        original = Uint16Vector1(data=[Uint16(0xABCD)])

        encoded = original.encode_bytes()
        decoded = Uint16Vector1.decode_bytes(encoded)

        assert len(decoded) == 1
        assert decoded[0] == Uint16(0xABCD)
        assert encoded == b"\xcd\xab"

    def test_single_element_list_roundtrip(self) -> None:
        """Single-element list roundtrips correctly."""
        original = Uint64List1(data=[Uint64(42)])

        encoded = original.encode_bytes()
        decoded = Uint64List1.decode_bytes(encoded)

        assert len(decoded) == 1
        assert decoded[0] == Uint64(42)

    def test_single_bit_bitvector_true(self) -> None:
        """Single-bit bitvector with True value."""
        original = Bitvector1(data=[Boolean(True)])

        encoded = original.encode_bytes()
        decoded = Bitvector1.decode_bytes(encoded)

        assert len(decoded.data) == 1
        assert decoded.data[0] == Boolean(True)
        assert encoded == b"\x01"

    def test_single_bit_bitvector_false(self) -> None:
        """Single-bit bitvector with False value."""
        original = Bitvector1(data=[Boolean(False)])

        encoded = original.encode_bytes()
        decoded = Bitvector1.decode_bytes(encoded)

        assert len(decoded.data) == 1
        assert decoded.data[0] == Boolean(False)
        assert encoded == b"\x00"

    def test_single_bit_bitlist_true(self) -> None:
        """Single-bit bitlist with True value."""
        original = Bitlist1(data=[Boolean(True)])

        encoded = original.encode_bytes()
        decoded = Bitlist1.decode_bytes(encoded)

        assert len(decoded.data) == 1
        assert decoded.data[0] == Boolean(True)
        assert encoded == b"\x03"  # 0b11 = bit 0 (data) + bit 1 (delimiter)

    def test_single_bit_bitlist_false(self) -> None:
        """Single-bit bitlist with False value."""
        original = Bitlist1(data=[Boolean(False)])

        encoded = original.encode_bytes()
        decoded = Bitlist1.decode_bytes(encoded)

        assert len(decoded.data) == 1
        assert decoded.data[0] == Boolean(False)
        assert encoded == b"\x02"  # 0b10 = bit 0 (data=0) + bit 1 (delimiter)

    def test_single_field_container_roundtrip(self) -> None:
        """Single-field container roundtrips correctly."""
        original = SingleFieldContainer(value=Uint64(0x123456789ABCDEF0))

        encoded = original.encode_bytes()
        decoded = SingleFieldContainer.decode_bytes(encoded)

        assert decoded.value == Uint64(0x123456789ABCDEF0)


# Zero value tests


class TestZeroValues:
    """Tests for zero values across all numeric types."""

    @pytest.mark.parametrize(
        "uint_type,byte_length",
        [
            (Uint8, 1),
            (Uint16, 2),
            (Uint32, 4),
            (Uint64, 8),
        ],
    )
    def test_zero_uint_roundtrip(self, uint_type: type[BaseUint], byte_length: int) -> None:
        """Zero value for each uint type roundtrips correctly."""
        original = uint_type(0)

        encoded = original.encode_bytes()
        decoded = uint_type.decode_bytes(encoded)

        assert decoded == uint_type(0)
        assert encoded == b"\x00" * byte_length

    def test_zero_boolean_roundtrip(self) -> None:
        """Boolean False (zero) roundtrips correctly."""
        original = Boolean(False)

        encoded = original.encode_bytes()
        decoded = Boolean.decode_bytes(encoded)

        assert decoded == Boolean(False)
        assert encoded == b"\x00"


# Maximum value tests


class TestMaximumValues:
    """Tests for maximum values across all numeric types."""

    @pytest.mark.parametrize(
        "uint_type,max_value",
        [
            (Uint8, 0xFF),
            (Uint16, 0xFFFF),
            (Uint32, 0xFFFFFFFF),
            (Uint64, 0xFFFFFFFFFFFFFFFF),
        ],
    )
    def test_max_uint_roundtrip(self, uint_type: type[BaseUint], max_value: int) -> None:
        """Maximum value for each uint type roundtrips correctly."""
        original = uint_type(max_value)

        encoded = original.encode_bytes()
        decoded = uint_type.decode_bytes(encoded)

        assert decoded == uint_type(max_value)
        assert int(decoded) == max_value

    def test_max_boolean_roundtrip(self) -> None:
        """Boolean True (max) roundtrips correctly."""
        original = Boolean(True)

        encoded = original.encode_bytes()
        decoded = Boolean.decode_bytes(encoded)

        assert decoded == Boolean(True)
        assert encoded == b"\x01"


# Byte boundary tests for bitfields


class TestByteBoundaries:
    """Tests for bitfields at byte boundaries."""

    def test_bitvector_7_bits(self) -> None:
        """Non-byte-aligned bitvector packs correctly."""
        bits = [Boolean(i % 2 == 0) for i in range(7)]  # Alternating pattern
        original = Bitvector7(data=bits)

        encoded = original.encode_bytes()
        decoded = Bitvector7.decode_bytes(encoded)

        assert len(decoded.data) == 7
        for i, bit in enumerate(decoded.data):
            assert bit == Boolean(i % 2 == 0)

    def test_bitvector_8_bits(self) -> None:
        """Byte-aligned bitvector (8 bits) roundtrips correctly."""
        bits = [Boolean(True)] * 8
        original = Bitvector8(data=bits)

        encoded = original.encode_bytes()
        decoded = Bitvector8.decode_bytes(encoded)

        assert encoded == b"\xff"
        assert len(decoded.data) == 8
        assert all(b == Boolean(True) for b in decoded.data)

    def test_bitvector_9_bits(self) -> None:
        """Bitvector spanning partial second byte roundtrips correctly."""
        bits = [Boolean(True)] * 9
        original = Bitvector9(data=bits)

        encoded = original.encode_bytes()
        decoded = Bitvector9.decode_bytes(encoded)

        # 9 bits all true: first byte = 0xFF, second byte = 0x01
        assert encoded == b"\xff\x01"
        assert len(decoded.data) == 9

    def test_bitlist_at_byte_boundary(self) -> None:
        """Bitlist with exactly 8 bits puts delimiter in new byte."""
        bits = [Boolean(True)] * 8
        original = Bitlist8(data=bits)

        encoded = original.encode_bytes()
        decoded = Bitlist8.decode_bytes(encoded)

        # 8 data bits all 1s: 0xFF, then delimiter byte: 0x01
        assert encoded == b"\xff\x01"
        assert len(decoded.data) == 8

    def test_bitlist_partial_byte(self) -> None:
        """Bitlist with partial byte puts delimiter in same byte."""
        bits = [Boolean(True)] * 3  # 3 bits
        original = Bitlist8(data=bits)

        encoded = original.encode_bytes()
        decoded = Bitlist8.decode_bytes(encoded)

        # 3 data bits (111) + delimiter at bit 3 = 0b00001111 = 0x0F
        assert encoded == b"\x0f"
        assert len(decoded.data) == 3


# Hash tree root tests for edge cases


class TestHashTreeRootEdgeCases:
    """Tests for hash_tree_root on edge case values."""

    def test_htr_empty_list(self) -> None:
        """Hash tree root of empty list is deterministic."""
        empty_list = Uint8List8(data=[])

        root = hash_tree_root(empty_list)

        assert isinstance(root, Bytes32)
        assert len(root) == 32

    def test_htr_empty_bitlist(self) -> None:
        """Hash tree root of empty bitlist is deterministic."""
        empty_bitlist = Bitlist256(data=[])

        root = hash_tree_root(empty_bitlist)

        assert isinstance(root, Bytes32)
        assert len(root) == 32

    def test_htr_zero_uint(self) -> None:
        """Hash tree root of zero is a zero-padded chunk."""
        zero = Uint64(0)

        root = hash_tree_root(zero)

        assert root == Bytes32(b"\x00" * 32)

    def test_htr_single_element_vector(self) -> None:
        """Hash tree root of single-element vector."""
        vec = Uint16Vector1(data=[Uint16(0xABCD)])

        root = hash_tree_root(vec)

        # Single element packed into chunk
        expected = Bytes32(b"\xcd\xab" + b"\x00" * 30)
        assert root == expected


# All-fixed container tests


class TestAllFixedContainer:
    """Tests for containers with all fixed-size fields."""

    def test_all_fixed_container_roundtrip(self) -> None:
        """Container with all fixed-size fields roundtrips correctly."""
        original = AllFixedContainer(
            a=Uint8(0x12), b=Uint16(0x3456), c=Uint32(0x789ABCDE), d=Uint64(0xFEDCBA9876543210)
        )

        encoded = original.encode_bytes()
        decoded = AllFixedContainer.decode_bytes(encoded)

        assert decoded.a == Uint8(0x12)
        assert decoded.b == Uint16(0x3456)
        assert decoded.c == Uint32(0x789ABCDE)
        assert decoded.d == Uint64(0xFEDCBA9876543210)

    def test_all_fixed_container_size(self) -> None:
        """Container with all fixed fields has predictable size."""
        original = AllFixedContainer(a=Uint8(0), b=Uint16(0), c=Uint32(0), d=Uint64(0))

        encoded = original.encode_bytes()

        # 1 + 2 + 4 + 8 = 15 bytes
        assert len(encoded) == 15
