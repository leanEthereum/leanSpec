"""Tests for boundary values in SSZ collections and types."""

from __future__ import annotations

import pytest

from lean_spec.types.bitfields import BaseBitlist, BaseBitvector
from lean_spec.types.boolean import Boolean
from lean_spec.types.byte_arrays import BaseByteList
from lean_spec.types.collections import SSZList, SSZVector
from lean_spec.types.container import Container
from lean_spec.types.exceptions import SSZValueError
from lean_spec.types.uint import BaseUint, Uint8, Uint16, Uint32, Uint64

# Test types with small limits for testing boundaries


class Uint8List4(SSZList[Uint8]):
    """List with limit of 4 elements."""

    LIMIT = 4


class Uint64List2(SSZList[Uint64]):
    """List with limit of 2 elements."""

    LIMIT = 2


class Bitlist4(BaseBitlist):
    """Bitlist with limit of 4 bits."""

    LIMIT = 4


class Bitlist8(BaseBitlist):
    """Bitlist with limit of 8 bits."""

    LIMIT = 8


class Bitlist256(BaseBitlist):
    """Bitlist with larger limit for chunk boundary testing."""

    LIMIT = 256


class Bitvector32(BaseBitvector):
    """Bitvector at chunk boundary."""

    LENGTH = 32


class Bitvector256(BaseBitvector):
    """Bitvector spanning full chunk."""

    LENGTH = 256


class ByteList4(BaseByteList):
    """ByteList with small limit."""

    LIMIT = 4


class ByteList32(BaseByteList):
    """ByteList at chunk boundary."""

    LIMIT = 32


# Variable-size container for list boundary testing


class VarContainer(Container):
    """Container with variable-size field."""

    header: Uint16
    items: Uint64List2


class VarContainerList2(SSZList):
    """List of variable-size containers with limit 2."""

    ELEMENT_TYPE = VarContainer
    LIMIT = 2


# Tests for collections at exactly LIMIT


class TestCollectionsAtLimit:
    """Tests for collections with exactly LIMIT elements."""

    def test_list_at_limit(self) -> None:
        """List with exactly LIMIT elements is valid."""
        original = Uint8List4(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4)])

        encoded = original.encode_bytes()
        decoded = Uint8List4.decode_bytes(encoded)

        assert len(decoded) == 4
        assert list(decoded) == [Uint8(1), Uint8(2), Uint8(3), Uint8(4)]

    def test_bitlist_at_limit(self) -> None:
        """Bitlist with exactly LIMIT bits is valid."""
        bits = [Boolean(True), Boolean(False), Boolean(True), Boolean(False)]
        original = Bitlist4(data=bits)

        encoded = original.encode_bytes()
        decoded = Bitlist4.decode_bytes(encoded)

        assert len(decoded.data) == 4
        assert list(decoded.data) == bits

    def test_bytelist_at_limit(self) -> None:
        """ByteList with exactly LIMIT bytes is valid."""
        original = ByteList4(data=b"\x01\x02\x03\x04")

        encoded = original.encode_bytes()
        decoded = ByteList4.decode_bytes(encoded)

        assert decoded.data == b"\x01\x02\x03\x04"

    def test_var_container_list_at_limit(self) -> None:
        """Variable-size container list at limit roundtrips correctly."""
        original = VarContainerList2(
            data=[
                VarContainer(header=Uint16(1), items=Uint64List2(data=[Uint64(100)])),
                VarContainer(header=Uint16(2), items=Uint64List2(data=[Uint64(200), Uint64(300)])),
            ]
        )

        encoded = original.encode_bytes()
        decoded = VarContainerList2.decode_bytes(encoded)

        assert len(decoded) == 2
        assert decoded[0].header == Uint16(1)
        assert decoded[1].items[1] == Uint64(300)


# Tests for collections at LIMIT - 1


class TestCollectionsAtLimitMinus1:
    """Tests for collections with LIMIT - 1 elements."""

    def test_list_at_limit_minus_1(self) -> None:
        """List with LIMIT - 1 elements is valid."""
        original = Uint8List4(data=[Uint8(1), Uint8(2), Uint8(3)])  # 3 elements, limit is 4

        encoded = original.encode_bytes()
        decoded = Uint8List4.decode_bytes(encoded)

        assert len(decoded) == 3

    def test_bitlist_at_limit_minus_1(self) -> None:
        """Bitlist with LIMIT - 1 bits is valid."""
        bits = [Boolean(True), Boolean(True), Boolean(True)]  # 3 bits, limit is 4
        original = Bitlist4(data=bits)

        encoded = original.encode_bytes()
        decoded = Bitlist4.decode_bytes(encoded)

        assert len(decoded.data) == 3


# Tests for collections exceeding LIMIT


class TestCollectionsExceedingLimit:
    """Tests for collections that exceed LIMIT."""

    def test_list_exceeds_limit_on_construction(self) -> None:
        """List construction with LIMIT + 1 elements raises error."""
        with pytest.raises(SSZValueError, match="exceeds limit"):
            Uint8List4(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4), Uint8(5)])

    def test_list_exceeds_limit_on_decode(self) -> None:
        """Decoding list data with too many elements raises error."""
        # Create raw bytes for 5 Uint8 elements (limit is 4)
        data = b"\x01\x02\x03\x04\x05"

        with pytest.raises(SSZValueError, match="exceeds limit"):
            Uint8List4.decode_bytes(data)

    def test_bitlist_exceeds_limit_on_construction(self) -> None:
        """Bitlist construction with LIMIT + 1 bits raises error."""
        bits = [Boolean(True)] * 5  # 5 bits, limit is 4

        with pytest.raises(SSZValueError, match="exceeds limit"):
            Bitlist4(data=bits)

    def test_bitlist_exceeds_limit_on_decode(self) -> None:
        """Decoding bitlist with too many bits raises error."""
        # Create bytes with 5 data bits + delimiter at bit 5
        # 0b00111111 = 0x3F (5 bits of data + delimiter at position 5)
        data = b"\x3f"

        with pytest.raises(SSZValueError, match="exceeds limit"):
            Bitlist4.decode_bytes(data)


# Tests for chunk boundary values


class TestChunkBoundaries:
    """Tests for values at Merkle chunk boundaries (32 bytes = 256 bits)."""

    def test_bitvector_at_chunk_boundary(self) -> None:
        """Bitvector[256] (exactly one chunk) roundtrips correctly."""
        bits = [Boolean(i % 2 == 0) for i in range(256)]
        original = Bitvector256(data=bits)

        encoded = original.encode_bytes()
        decoded = Bitvector256.decode_bytes(encoded)

        assert len(decoded.data) == 256
        assert len(encoded) == 32  # Exactly one chunk

    def test_bitlist_at_chunk_boundary(self) -> None:
        """Bitlist with 256 bits (one chunk of data) roundtrips correctly."""
        bits = [Boolean(True)] * 256
        original = Bitlist256(data=bits)

        encoded = original.encode_bytes()
        decoded = Bitlist256.decode_bytes(encoded)

        assert len(decoded.data) == 256
        # 256 bits of data (32 bytes) + 1 delimiter byte
        assert len(encoded) == 33

    def test_bytelist_at_chunk_boundary(self) -> None:
        """ByteList with 32 bytes (exactly one chunk) roundtrips correctly."""
        original = ByteList32(data=bytes(range(32)))

        encoded = original.encode_bytes()
        decoded = ByteList32.decode_bytes(encoded)

        assert decoded.data == bytes(range(32))
        assert len(encoded) == 32

    def test_bitvector_partial_chunk(self) -> None:
        """Bitvector[32] (4 bytes, partial chunk) roundtrips correctly."""
        bits = [Boolean(True)] * 32
        original = Bitvector32(data=bits)

        encoded = original.encode_bytes()
        decoded = Bitvector32.decode_bytes(encoded)

        assert len(decoded.data) == 32
        assert len(encoded) == 4
        assert encoded == b"\xff\xff\xff\xff"


# Tests for offset overflow scenarios


class TestOffsetBoundaries:
    """Tests for offset table boundary conditions."""

    def test_list_with_maximum_elements_at_limit(self) -> None:
        """List at exactly limit with variable-size elements."""
        max_u64 = Uint64((1 << 64) - 1)
        original = VarContainerList2(
            data=[
                VarContainer(
                    header=Uint16(0xFFFF),
                    items=Uint64List2(data=[max_u64, max_u64]),
                ),
                VarContainer(
                    header=Uint16(0xFFFF),
                    items=Uint64List2(data=[max_u64, max_u64]),
                ),
            ]
        )

        encoded = original.encode_bytes()
        decoded = VarContainerList2.decode_bytes(encoded)

        assert len(decoded) == 2
        assert decoded[0].items[0] == Uint64(0xFFFFFFFFFFFFFFFF)


# Tests for vector length validation


class TestVectorLengthValidation:
    """Tests for vector length boundary conditions."""

    def test_vector_exact_length(self) -> None:
        """Vector must have exactly LENGTH elements."""

        class Uint16Vector3(SSZVector[Uint16]):
            LENGTH = 3

        original = Uint16Vector3(data=[Uint16(1), Uint16(2), Uint16(3)])

        encoded = original.encode_bytes()
        decoded = Uint16Vector3.decode_bytes(encoded)

        assert len(decoded) == 3

    def test_vector_wrong_length_construction(self) -> None:
        """Vector construction with wrong number of elements raises error."""

        class Uint16Vector3(SSZVector[Uint16]):
            LENGTH = 3

        with pytest.raises(SSZValueError, match="requires exactly 3 elements"):
            Uint16Vector3(data=[Uint16(1), Uint16(2)])


# Tests for large serialized sizes


class TestLargeSerializedSizes:
    """Tests for handling larger serialized data."""

    def test_large_bitlist_roundtrip(self) -> None:
        """Large bitlist (near limit) roundtrips correctly."""
        bits = [Boolean(i % 3 == 0) for i in range(256)]  # 256 bits
        original = Bitlist256(data=bits)

        encoded = original.encode_bytes()
        decoded = Bitlist256.decode_bytes(encoded)

        assert len(decoded.data) == 256
        for i, bit in enumerate(decoded.data):
            assert bit == Boolean(i % 3 == 0)

    def test_list_of_max_uints_roundtrip(self) -> None:
        """List of maximum Uint64 values roundtrips correctly."""
        max_val = (1 << 64) - 1
        original = Uint64List2(data=[Uint64(max_val), Uint64(max_val)])

        encoded = original.encode_bytes()
        decoded = Uint64List2.decode_bytes(encoded)

        assert len(decoded) == 2
        assert decoded[0] == Uint64(max_val)
        assert decoded[1] == Uint64(max_val)


# Tests for numeric type boundaries


class TestNumericBoundaries:
    """Tests for numeric type min/max boundaries."""

    @pytest.mark.parametrize(
        "uint_type,max_val",
        [
            (Uint8, (1 << 8) - 1),
            (Uint16, (1 << 16) - 1),
            (Uint32, (1 << 32) - 1),
            (Uint64, (1 << 64) - 1),
        ],
    )
    def test_uint_max_boundary(self, uint_type: type[BaseUint], max_val: int) -> None:
        """Maximum value for uint type roundtrips correctly."""
        original = uint_type(max_val)

        encoded = original.encode_bytes()
        decoded = uint_type.decode_bytes(encoded)

        assert decoded == uint_type(max_val)
        assert int(decoded) == max_val

    @pytest.mark.parametrize(
        "uint_type,bits",
        [
            (Uint8, 8),
            (Uint16, 16),
            (Uint32, 32),
            (Uint64, 64),
        ],
    )
    def test_uint_overflow_rejected(self, uint_type: type[BaseUint], bits: int) -> None:
        """Values exceeding max are rejected."""
        with pytest.raises(SSZValueError, match="out of range"):
            uint_type((1 << bits))  # One above max

    @pytest.mark.parametrize("uint_type", [Uint8, Uint16, Uint32, Uint64])
    def test_uint_negative_rejected(self, uint_type: type[BaseUint]) -> None:
        """Negative values are rejected."""
        with pytest.raises(SSZValueError, match="out of range"):
            uint_type(-1)
