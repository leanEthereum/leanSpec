"""Tests for malformed SSZ data handling."""

from __future__ import annotations

import pytest

from lean_spec.types.bitfields import BaseBitlist, BaseBitvector
from lean_spec.types.byte_arrays import BaseByteList
from lean_spec.types.collections import SSZList, SSZVector
from lean_spec.types.container import Container
from lean_spec.types.exceptions import SSZSerializationError, SSZValueError
from lean_spec.types.uint import Uint16, Uint32, Uint64
from lean_spec.types.union import SSZUnion

# Test type definitions


class Uint64List8(SSZList[Uint64]):
    """List of up to 8 Uint64 values."""

    LIMIT = 8


class VarContainer(Container):
    """Container with a variable-size field."""

    a: Uint16
    b: Uint64List8


class VarContainerList4(SSZList):
    """List of variable-size containers."""

    ELEMENT_TYPE = VarContainer
    LIMIT = 4


class VarVector2(SSZVector):
    """Vector of 2 variable-size containers."""

    ELEMENT_TYPE = VarContainer
    LENGTH = 2


class Bitlist64(BaseBitlist):
    """Bitlist with max 64 bits."""

    LIMIT = 64


class Bitvector8(BaseBitvector):
    """Bitvector with exactly 8 bits."""

    LENGTH = 8


class ByteList32(BaseByteList):
    """ByteList with max 32 bytes."""

    LIMIT = 32


class UnionUint16Uint32(SSZUnion):
    """Union of Uint16 and Uint32."""

    OPTIONS = (Uint16, Uint32)


class UnionNoneUint16(SSZUnion):
    """Union with None option."""

    OPTIONS = (None, Uint16)


# Offset validation tests


class TestInvalidOffsets:
    """Tests for invalid offset tables in variable-size collections."""

    def test_list_offsets_not_monotonic(self) -> None:
        """Offsets must be monotonically non-decreasing."""
        # Build malformed data: 2 elements where second offset < first offset
        # Offset table: [8, 4] (8 bytes for 2 offsets, then data)
        # First offset should be 8, second should be >= 8
        data = (
            b"\x08\x00\x00\x00"  # First offset: 8
            b"\x04\x00\x00\x00"  # Second offset: 4 (invalid - less than first)
            b"\x01\x00"  # First element data
            b"\x02\x00"  # Second element data
        )

        with pytest.raises(SSZSerializationError, match="monotonically increasing"):
            VarContainerList4.decode_bytes(data)

    def test_list_offset_exceeds_scope(self) -> None:
        """Final offset must not exceed total scope."""
        # Build data where offset points beyond the data
        # The second offset 255 exceeds scope of 12 bytes
        # This triggers monotonically increasing check since offsets become [8, 255, 12]
        data = (
            b"\x08\x00\x00\x00"  # First offset: 8
            b"\xff\x00\x00\x00"  # Second offset: 255 (way beyond scope)
            b"\x01\x00\x02\x00"  # Some element data (total scope = 12)
        )

        with pytest.raises(SSZSerializationError, match="monotonically"):
            VarContainerList4.decode_bytes(data)

    def test_vector_offsets_not_monotonic(self) -> None:
        """Vector offsets must also be monotonically non-decreasing."""
        # VarVector2 has 2 elements, so offset table is 8 bytes
        data = (
            b"\x08\x00\x00\x00"  # First offset: 8
            b"\x06\x00\x00\x00"  # Second offset: 6 (invalid - less than first)
            b"\x01\x00\x02\x00"  # Some element data
        )

        with pytest.raises(SSZSerializationError, match="(monotonically|invalid)"):
            VarVector2.decode_bytes(data)

    def test_list_first_offset_invalid(self) -> None:
        """First offset must match the expected offset table size."""
        # For 2 elements, first offset should be 8 (2 * 4 bytes)
        # With first offset 12, it reads 3 offsets worth, causing garbage data
        # to be interpreted as an offset, failing the monotonicity check
        data = (
            b"\x0c\x00\x00\x00"  # First offset: 12 (wrong - should be 8 for 2 elements)
            b"\x10\x00\x00\x00"  # Second offset
            b"\x01\x00\x02\x00"
            b"\x03\x00\x04\x00"
        )

        with pytest.raises(SSZSerializationError, match="monotonically"):
            VarContainerList4.decode_bytes(data)


# Truncated data tests


class TestTruncatedData:
    """Tests for handling truncated SSZ data."""

    def test_truncated_uint64(self) -> None:
        """Uint64 requires exactly 8 bytes."""
        data = b"\x01\x02\x03\x04\x05"  # Only 5 bytes

        with pytest.raises(SSZSerializationError, match="expected 8 bytes"):
            Uint64.decode_bytes(data)

    def test_truncated_list_element(self) -> None:
        """List deserialization fails on truncated element data."""
        # Valid offset table but element data is too short
        data = (
            b"\x08\x00\x00\x00"  # First offset: 8
            b"\x0a\x00\x00\x00"  # Second offset: 10 (claims 2 bytes for first elem)
            b"\x01"  # Only 1 byte of data (should be 2 for a Uint16 container)
        )

        with pytest.raises(SSZSerializationError):
            VarContainerList4.decode_bytes(data)

    def test_truncated_bitvector(self) -> None:
        """Bitvector requires exactly the right number of bytes."""
        # Bitvector8 needs 1 byte, provide none
        data = b""

        with pytest.raises(SSZValueError, match="expected 1 bytes"):
            Bitvector8.decode_bytes(data)

    def test_truncated_bytelist(self) -> None:
        """Stream ends before reading expected data."""
        # ByteList32 with scope claiming more data than available
        data = b"\x01\x02\x03"

        # This should work - it's valid data of length 3
        result = ByteList32.decode_bytes(data)
        assert len(result.data) == 3


# Bitlist delimiter tests


class TestBitlistDelimiter:
    """Tests for bitlist delimiter bit handling."""

    def test_bitlist_no_delimiter_bit(self) -> None:
        """Bitlist must have a delimiter bit set."""
        # All zero bytes - no delimiter bit present
        data = b"\x00"

        with pytest.raises(SSZSerializationError, match="no delimiter bit"):
            Bitlist64.decode_bytes(data)

    def test_bitlist_empty_data(self) -> None:
        """Empty data is invalid for bitlist."""
        data = b""

        with pytest.raises(SSZSerializationError, match="cannot decode empty"):
            Bitlist64.decode_bytes(data)

    def test_bitlist_all_zeros(self) -> None:
        """Multiple zero bytes with no delimiter is invalid."""
        data = b"\x00\x00\x00"

        with pytest.raises(SSZSerializationError, match="no delimiter bit"):
            Bitlist64.decode_bytes(data)

    def test_bitlist_valid_empty(self) -> None:
        """Valid empty bitlist has just the delimiter byte."""
        data = b"\x01"  # Just delimiter bit, no data bits

        result = Bitlist64.decode_bytes(data)
        assert len(result.data) == 0

    def test_bitlist_exceeds_limit(self) -> None:
        """Bitlist with more bits than LIMIT is rejected."""
        # Create data with 65 bits (delimiter at bit 65), but LIMIT is 64
        data = b"\xff" * 8 + b"\x02"  # 64 bits of data + delimiter at bit 65

        with pytest.raises(SSZValueError, match="exceeds limit"):
            Bitlist64.decode_bytes(data)


# Union selector tests


class TestUnionSelector:
    """Tests for union selector validation."""

    def test_union_selector_out_of_range(self) -> None:
        """Selector must be within the OPTIONS range."""
        # UnionUint16Uint32 has OPTIONS = (Uint16, Uint32), valid selectors are 0, 1
        data = (
            b"\x02"  # Selector: 2 (invalid - only 0 and 1 are valid)
            b"\xab\xcd"  # Some value data
        )

        with pytest.raises(SSZValueError, match="selector 2 out of range"):
            UnionUint16Uint32.decode_bytes(data)

    def test_union_selector_max_invalid(self) -> None:
        """Selector value 128+ is invalid even for large unions."""
        # Any selector >= 128 is invalid (max 127 options)
        data = (
            b"\x80"  # Selector: 128 (invalid)
            b"\xab\xcd"
        )

        with pytest.raises(SSZValueError, match="selector 128 out of range"):
            UnionUint16Uint32.decode_bytes(data)

    def test_union_none_arm_with_data(self) -> None:
        """None arm must have no payload bytes."""
        # UnionNoneUint16 selector=0 means None, should have no data
        data = (
            b"\x00"  # Selector: 0 (None)
            b"\xab\xcd"  # Extra data (invalid for None arm)
        )

        with pytest.raises(SSZSerializationError, match="None arm must have no payload"):
            UnionNoneUint16.decode_bytes(data)

    def test_union_valid_none_arm(self) -> None:
        """Valid None arm has just the selector byte."""
        data = b"\x00"  # Selector: 0 (None), no payload

        result = UnionNoneUint16.decode_bytes(data)
        assert result.selector == 0
        assert result.value is None

    def test_union_scope_too_small(self) -> None:
        """Union needs at least 1 byte for selector."""
        data = b""

        with pytest.raises(SSZSerializationError, match="scope too small"):
            UnionUint16Uint32.decode_bytes(data)


# Excess bytes tests


class TestExcessBytes:
    """Tests for handling excess bytes after valid data."""

    def test_uint_excess_bytes(self) -> None:
        """Fixed-size type rejects excess bytes."""
        # Uint16 needs exactly 2 bytes
        data = b"\x01\x02\x03"  # 3 bytes

        with pytest.raises(SSZSerializationError, match="expected 2 bytes"):
            Uint16.decode_bytes(data)

    def test_bitvector_excess_bytes(self) -> None:
        """Bitvector rejects excess bytes."""
        # Bitvector8 needs exactly 1 byte
        data = b"\xff\xff"  # 2 bytes

        with pytest.raises(SSZValueError, match="expected 1 bytes"):
            Bitvector8.decode_bytes(data)


# Container field validation tests


class TestContainerValidation:
    """Tests for container field validation during deserialization."""

    def test_container_missing_field_data(self) -> None:
        """Container with insufficient data for fixed fields fails."""
        # VarContainer has: a (Uint16, 2 bytes) + offset (4 bytes) = 6 bytes minimum
        data = b"\x01\x02"  # Only 2 bytes

        with pytest.raises(SSZSerializationError):
            VarContainer.decode_bytes(data)


# List limit validation tests


class TestListLimitValidation:
    """Tests for list limit enforcement during deserialization."""

    def test_list_exceeds_limit_fixed_elements(self) -> None:
        """List with more elements than LIMIT is rejected."""
        # Uint64List8 has LIMIT=8, create data for 9 elements
        data = b"\x01\x00\x00\x00\x00\x00\x00\x00" * 9  # 9 Uint64 values

        with pytest.raises(SSZValueError, match="exceeds limit"):
            Uint64List8.decode_bytes(data)

    def test_list_at_limit(self) -> None:
        """List with exactly LIMIT elements is valid."""
        data = b"\x01\x00\x00\x00\x00\x00\x00\x00" * 8  # 8 Uint64 values

        result = Uint64List8.decode_bytes(data)
        assert len(result) == 8


# Vector length validation tests


class TestVectorLengthValidation:
    """Tests for vector length enforcement during deserialization."""

    def test_vector_wrong_length_fixed_elements(self) -> None:
        """Vector with wrong number of elements fails."""

        class Uint16Vector3(SSZVector[Uint16]):
            LENGTH = 3

        # Provide data for 2 elements instead of 3
        data = b"\x01\x00\x02\x00"  # 2 Uint16 values

        with pytest.raises(SSZSerializationError, match="expected 6 bytes"):
            Uint16Vector3.decode_bytes(data)

    def test_vector_first_offset_wrong(self) -> None:
        """Vector first offset must match expected value."""
        # VarVector2 expects first offset = 8 (2 * 4 bytes)
        data = (
            b"\x04\x00\x00\x00"  # First offset: 4 (wrong - should be 8)
            b"\x06\x00\x00\x00"  # Second offset
            b"\x01\x00"
            b"\x02\x00"
        )

        with pytest.raises(SSZSerializationError, match="invalid offset"):
            VarVector2.decode_bytes(data)
