""" "Tests for the Bitvector and Bitlist types."""

import io
from typing import Any

import pytest
from pydantic import ValidationError, create_model
from typing_extensions import Tuple

from lean_spec.types.bitfields import Bitlist, Bitvector


class TestBitvector:
    """Tests for the fixed-length, immutable Bitvector type."""

    def test_class_getitem_creates_specialized_type(self) -> None:
        """Tests that `Bitvector[N]` creates a new, distinct type with the correct length."""
        vec_type_8 = Bitvector[8]  # type: ignore
        vec_type_16 = Bitvector[16]  # type: ignore
        assert vec_type_8 is not Bitvector[16]  # type: ignore
        assert vec_type_8.LENGTH == 8
        assert vec_type_16.LENGTH == 16
        assert "Bitvector[8]" in repr(vec_type_8)

    @pytest.mark.parametrize("invalid_length", [0, -1, 1.0, "8"])
    def test_class_getitem_with_invalid_length_raises_error(self, invalid_length: Any) -> None:
        """Tests that creating a Bitvector type with a non-positive integer length fails."""
        with pytest.raises(TypeError):
            _ = Bitvector[invalid_length]  # type: ignore

    def test_instantiate_raw_type_raises_error(self) -> None:
        """Tests that the raw, non-specialized Bitvector cannot be instantiated."""
        with pytest.raises(TypeError, match="Cannot instantiate raw Bitvector"):
            Bitvector([])

    def test_instantiation_success(self) -> None:
        """Tests successful instantiation with the correct number of valid boolean items."""
        vec_type = Bitvector[4]  # type: ignore
        instance = vec_type([True, False, 1, 0])
        assert len(instance) == 4
        assert instance == (True, False, True, False)

    @pytest.mark.parametrize(
        "values",
        [
            [True, False, True],  # Too few
            [True, False, True, False, True],  # Too many
        ],
    )
    def test_instantiation_with_wrong_length_raises_error(self, values: list[bool]) -> None:
        """Tests that providing the wrong number of items during instantiation fails."""
        vec_type = Bitvector[4]  # type: ignore
        with pytest.raises(ValueError, match="requires exactly 4 items"):
            vec_type(values)

    def test_pydantic_validation_accepts_valid_list(self) -> None:
        """Tests that Pydantic validation correctly accepts a valid list of booleans."""
        model = create_model("Model", value=(Bitvector[4], ...))  # type: ignore
        instance: Any = model(value=[True, False, True, False])
        assert isinstance(instance.value, Bitvector[4])  # type: ignore
        assert instance.value == (True, False, True, False)

    @pytest.mark.parametrize(
        "invalid_value",
        [
            [True, False, True],  # Too short
            [True, False, True, False, True],  # Too long
            (True, 1, 0, "not a bool"),  # Invalid type in list
        ],
    )
    def test_pydantic_validation_rejects_invalid_values(self, invalid_value: Any) -> None:
        """
        Tests that Pydantic validation rejects lists of the wrong length or with invalid types.
        """
        model = create_model("Model", value=(Bitvector[4], ...))  # type: ignore
        with pytest.raises(ValidationError):
            model(value=invalid_value)

    def test_bitvector_is_immutable(self) -> None:
        """Tests that attempting to change an item in a Bitvector raises a TypeError."""
        vec = Bitvector[2]([True, False])  # type: ignore
        with pytest.raises(TypeError):
            vec[0] = False


class TestBitlist:
    """Tests for the variable-length, capacity-limited Bitlist type."""

    def test_class_getitem_creates_specialized_type(self) -> None:
        """Tests that `Bitlist[N]` creates a new, distinct type with the correct limit."""
        list_type_8 = Bitlist[8]  # type: ignore
        list_type_16 = Bitlist[16]  # type: ignore
        assert list_type_8 is not Bitlist[16]  # type: ignore
        assert list_type_8.LIMIT == 8
        assert list_type_16.LIMIT == 16
        assert "Bitlist[8]" in repr(list_type_8)

    def test_instantiate_raw_type_raises_error(self) -> None:
        """Tests that the raw, non-specialized Bitlist cannot be instantiated."""
        with pytest.raises(TypeError, match="Cannot instantiate raw Bitlist"):
            Bitlist([])

    def test_instantiation_success(self) -> None:
        """Tests successful instantiation with a valid number of items."""
        list_type = Bitlist[8]  # type: ignore
        instance = list_type([True, False, 1, 0])
        assert len(instance) == 4
        assert instance == [True, False, True, False]

    def test_instantiation_over_limit_raises_error(self) -> None:
        """Tests that providing more items than the limit during instantiation fails."""
        list_type = Bitlist[4]  # type: ignore
        with pytest.raises(ValueError, match="has a limit of 4 items"):
            list_type([True, False, True, False, True])

    def test_pydantic_validation_accepts_valid_list(self) -> None:
        """Tests that Pydantic validation correctly accepts a valid list of booleans."""
        model = create_model("Model", value=(Bitlist[8], ...))  # type: ignore
        instance: Any = model(value=[True, False, True, False])
        assert isinstance(instance.value, Bitlist[8])  # type: ignore
        assert len(instance.value) == 4

    @pytest.mark.parametrize(
        "invalid_value",
        [
            [True] * 9,  # Too long
            (True, 1, 0, "not a bool"),  # Invalid type in list
        ],
    )
    def test_pydantic_validation_rejects_invalid_values(self, invalid_value: Any) -> None:
        """Tests that Pydantic validation rejects lists that are too long or have invalid types."""
        model = create_model("Model", value=(Bitlist[8], ...))  # type: ignore
        with pytest.raises(ValidationError):
            model(value=invalid_value)

    def test_append_within_limit(self) -> None:
        """Tests that `append` succeeds when the list is not full."""
        bl = Bitlist[4]([True, True])  # type: ignore
        bl.append(False)
        assert len(bl) == 3
        assert bl == [True, True, False]

    def test_append_at_limit_raises_error(self) -> None:
        """Tests that `append` fails when the list is at its capacity."""
        bl = Bitlist[4]([True] * 4)  # type: ignore
        with pytest.raises(ValueError, match="exceeds Bitlist\\[4\\] limit of 4 items"):
            bl.append(False)

    def test_extend_within_limit(self) -> None:
        """Tests that `extend` succeeds when the result is within the limit."""
        bl = Bitlist[8]([True, False])  # type: ignore
        bl.extend([1, 0, True])
        assert len(bl) == 5
        assert bl == [True, False, True, False, True]

    def test_extend_over_limit_raises_error(self) -> None:
        """Tests that `extend` fails if the result would exceed the capacity."""
        bl = Bitlist[4]([True, False])  # type: ignore
        with pytest.raises(ValueError, match="exceeds Bitlist\\[4\\] limit of 4 items"):
            bl.extend([True, False, True])

    def test_insert_within_limit(self) -> None:
        """Tests that `insert` succeeds when the list is not full."""
        bl = Bitlist[4]([True, False])  # type: ignore
        bl.insert(1, True)
        assert len(bl) == 3
        assert bl == [True, True, False]

    def test_insert_at_limit_raises_error(self) -> None:
        """Tests that `insert` fails when the list is at its capacity."""
        bl = Bitlist[4]([True] * 4)  # type: ignore
        with pytest.raises(ValueError, match="exceeds Bitlist\\[4\\] limit of 4 items"):
            bl.insert(0, False)

    def test_setitem_slice_over_limit_raises_error(self) -> None:
        """Tests that replacing a slice fails if it would cause the list to exceed its limit."""
        bl = Bitlist[4]([True, False, True])  # type: ignore
        with pytest.raises(ValueError, match="exceeds Bitlist\\[4\\] limit of 4 items"):
            bl[1:2] = [False, False, False, False]  # Replaces 1 item with 4 -> len becomes 6

    def test_add_over_limit_raises_error(self) -> None:
        """Tests that the `+` operator fails if the resulting list would be too long."""
        bl1 = Bitlist[4]([True, False])  # type: ignore
        bl2 = Bitlist[4]([True, False, True])  # type: ignore
        with pytest.raises(ValueError, match="exceeds Bitlist\\[4\\] limit of 4 items"):
            _ = bl1 + bl2

    def test_iadd_over_limit_raises_error(self) -> None:
        """Tests that the `+=` operator fails if the resulting list would be too long."""
        bl = Bitlist[4]([True, False])  # type: ignore
        with pytest.raises(ValueError, match="exceeds Bitlist\\[4\\] limit of 4 items"):
            bl += [True, False, True]


class TestBitfieldSerialization:
    """Tests the `encode_bytes` and `decode_bytes` methods for bitfields."""

    @pytest.mark.parametrize(
        "length, value, expected_hex",
        [
            (8, (True, True, False, True, False, True, False, False), "2b"),
            (4, (False, True, False, True), "0a"),
            (3, (False, True, False), "02"),
            (10, (1, False, True, False, False, False, True, True, False, True), "c502"),
        ],
    )
    def test_bitvector_serialization_deserialization(
        self, length: int, value: Tuple[bool, ...], expected_hex: str
    ) -> None:
        """Tests the round trip of serializing and deserializing for Bitvector."""
        vec_type = Bitvector[length]  # type: ignore
        instance = vec_type(value)

        # Test serialization
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex

        # Test deserialization
        decoded = vec_type.decode_bytes(encoded)
        assert decoded == instance

    @pytest.mark.parametrize(
        "limit, value, expected_hex",
        [
            (8, (), "01"),  # Empty list
            (8, (True, True, False, True, False, True, False, False), "2b01"),
            (4, (False, True, False, True), "1a"),
            (3, (False, True, False), "0a"),
            (16, (True, False, True, False, False, False, True, True, False, True), "c506"),
        ],
    )
    def test_bitlist_serialization_deserialization(
        self, limit: int, value: Tuple[bool, ...], expected_hex: str
    ) -> None:
        """Tests the round trip of serializing and deserializing for Bitlist."""
        list_type = Bitlist[limit]  # type: ignore
        instance = list_type(value)

        # Test serialization
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex

        # Test deserialization
        decoded = list_type.decode_bytes(encoded)
        assert decoded == instance

    def test_bitvector_decode_invalid_length(self) -> None:
        """Tests that Bitvector.decode_bytes fails for data of the wrong length."""
        vec_type = Bitvector[8]  # type: ignore
        with pytest.raises(ValueError, match="Invalid byte length for Bitvector\\[8\\]"):
            vec_type.decode_bytes(b"\x01\x02")  # Expects 1 byte, gets 2

    def test_bitlist_decode_invalid_data(self) -> None:
        """Tests that Bitlist.decode_bytes fails for invalid byte strings."""
        list_type = Bitlist[8]  # type: ignore
        with pytest.raises(ValueError, match="data cannot be empty"):
            list_type.decode_bytes(b"")
        with pytest.raises(ValueError, match="last byte cannot be zero"):
            list_type.decode_bytes(b"\xff\x00")


class TestBitfieldSSZ:
    """Tests the SSZType interface methods for bitfields."""

    def test_bitvector_ssz_properties(self) -> None:
        vec_type = Bitvector[10]  # type: ignore
        assert vec_type.is_fixed_size() is True
        assert vec_type.get_byte_length() == 2  # (10+7)//8

    def test_bitlist_ssz_properties(self) -> None:
        list_type = Bitlist[10]  # type: ignore
        assert list_type.is_fixed_size() is False
        with pytest.raises(TypeError):
            list_type.get_byte_length()

    def test_bitvector_deserialize_invalid_scope(self) -> None:
        vec_type = Bitvector[8]  # type: ignore
        stream = io.BytesIO(b"\xff")
        with pytest.raises(ValueError, match="Invalid scope"):
            vec_type.deserialize(stream, scope=2)

    def test_bitvector_deserialize_premature_end(self) -> None:
        vec_type = Bitvector[16]  # type: ignore
        stream = io.BytesIO(b"\xff")  # Only 1 byte, expects 2
        with pytest.raises(IOError, match="Stream ended prematurely"):
            vec_type.deserialize(stream, scope=2)

    def test_bitlist_deserialize_premature_end(self) -> None:
        list_type = Bitlist[16]  # type: ignore
        stream = io.BytesIO(b"\xff")  # Only 1 byte
        with pytest.raises(IOError, match="Stream ended prematurely"):
            list_type.deserialize(stream, scope=2)  # Scope says to read 2

    @pytest.mark.parametrize(
        "length,value,expected_hex",
        [
            (8, (1, 1, 0, 1, 0, 1, 0, 0), "2b"),
            (4, (0, 1, 0, 1), "0a"),
            (3, (0, 1, 0), "02"),
            (10, (1, 0, 1, 0, 0, 0, 1, 1, 0, 1), "c502"),
            (16, (1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1), "c5c2"),
            (512, tuple([1] * 512), "ff" * 64),
            (513, tuple([1] * 513), ("ff" * 64) + "01"),
        ],
    )
    def test_bitvector_encode_decode(
        self, length: int, value: Tuple[int, ...], expected_hex: str
    ) -> None:
        vec_t = Bitvector[length]  # type: ignore
        instance = vec_t(value)
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex

        # round-trip via classmethod
        decoded = vec_t.decode_bytes(encoded)
        assert decoded == instance

        # round-trip via stream serialize/deserialize
        stream = io.BytesIO()
        written = instance.serialize(stream)
        assert written == vec_t.get_byte_length()
        stream.seek(0)
        decoded2 = vec_t.deserialize(stream, scope=written)
        assert decoded2 == instance

    @pytest.mark.parametrize(
        "limit,value,expected_hex",
        [
            (8, (), "01"),
            (8, (1, 1, 0, 1, 0, 1, 0, 0), "2b01"),
            (4, (0, 1, 0, 1), "1a"),
            (3, (0, 1, 0), "0a"),
            (16, (1, 0, 1, 0, 0, 0, 1, 1, 0, 1), "c506"),
            (512, (1,), "03"),
            (512, tuple([1] * 512), ("ff" * 64) + "01"),
            (513, tuple([1] * 513), ("ff" * 64) + "03"),
        ],
    )
    def test_bitlist_encode_decode(
        self, limit: int, value: Tuple[int, ...], expected_hex: str
    ) -> None:
        list_t = Bitlist[limit]  # type: ignore
        instance = list_t(value)
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex

        # round-trip via classmethod
        decoded = list_t.decode_bytes(encoded)
        assert decoded == instance

        # round-trip via stream serialize/deserialize
        stream = io.BytesIO()
        written = instance.serialize(stream)
        # variable-size, so we assert the written size matches the encoding length
        assert written == len(encoded)
        stream.seek(0)
        decoded2 = list_t.deserialize(stream, scope=written)
        assert decoded2 == instance
