""" "Tests for the Bitvector and Bitlist types."""

import io
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError
from typing_extensions import Tuple

from lean_spec.types.bitfields import BaseBitlist, BaseBitvector
from lean_spec.types.boolean import Boolean
from lean_spec.types.exceptions import SSZSerializationError, SSZTypeError, SSZValueError

# Type alias for errors that can be SSZValueError or wrapped in ValidationError
ValueOrValidationError = (SSZValueError, ValidationError)


# Define bitfield types at module level for reuse and model classes
class Bitvector4(BaseBitvector):
    """A bitvector of exactly 4 bits."""

    LENGTH = 4


class Bitvector4Model(BaseModel):
    """Model for testing Pydantic validation of Bitvector4."""

    value: Bitvector4


class Bitlist8(BaseBitlist):
    """A bitlist with up to 8 bits."""

    LIMIT = 8


class Bitlist8Model(BaseModel):
    """Model for testing Pydantic validation of Bitlist8."""

    value: Bitlist8


class TestBitvector:
    """Tests for the fixed-length, immutable Bitvector type."""

    def test_class_creates_specialized_type(self) -> None:
        """Tests that concrete Bitvector classes have the correct length."""

        class Bitvector8(BaseBitvector):
            LENGTH = 8

        class Bitvector16(BaseBitvector):
            LENGTH = 16

        assert Bitvector8.LENGTH == 8
        assert Bitvector16.LENGTH == 16
        assert "Bitvector8" in repr(Bitvector8)

    def test_instantiate_raw_type_raises_error(self) -> None:
        """Tests that the raw, non-specialized BaseBitvector cannot be instantiated."""
        with pytest.raises(SSZTypeError, match="must define LENGTH"):
            BaseBitvector(data=[])

    def test_instantiation_success(self) -> None:
        """Tests successful instantiation with the correct number of valid boolean items."""
        instance = Bitvector4(data=[Boolean(True), Boolean(False), Boolean(1), Boolean(0)])
        assert len(instance) == 4
        assert instance == Bitvector4(
            data=[Boolean(True), Boolean(False), Boolean(True), Boolean(False)]
        )

    @pytest.mark.parametrize(
        "values",
        [
            [Boolean(True), Boolean(False), Boolean(True)],  # Too few
            [Boolean(True), Boolean(False), Boolean(True), Boolean(False), Boolean(True)],
        ],
    )
    def test_instantiation_with_wrong_length_raises_error(self, values: list[Boolean]) -> None:
        """Tests that providing the wrong number of items during instantiation fails."""
        with pytest.raises(ValueOrValidationError):
            Bitvector4(data=values)

    def test_pydantic_validation_accepts_valid_list(self) -> None:
        """Tests that Pydantic validation correctly accepts a valid list of booleans."""
        bits = [Boolean(True), Boolean(False), Boolean(True), Boolean(False)]
        instance = Bitvector4Model(value={"data": bits})  # type: ignore[arg-type]
        assert isinstance(instance.value, Bitvector4)
        assert instance.value == Bitvector4(data=bits)

    @pytest.mark.parametrize(
        "invalid_value",
        [
            {"data": [Boolean(True), Boolean(False), Boolean(True)]},  # Too short
            {"data": [Boolean(b) for b in [True, False, True, False, True]]},  # Too long
        ],
    )
    def test_pydantic_validation_rejects_invalid_values(self, invalid_value: Any) -> None:
        """Tests that Pydantic validation rejects lists of the wrong length."""
        with pytest.raises(ValueOrValidationError):
            Bitvector4Model(value=invalid_value)

    def test_bitvector_is_immutable(self) -> None:
        """Tests that attempting to change an item in a Bitvector raises a TypeError."""

        class Bitvector2(BaseBitvector):
            LENGTH = 2

        vec = Bitvector2(data=[Boolean(True), Boolean(False)])
        with pytest.raises(TypeError):
            vec[0] = False  # type: ignore[index]  # Should fail because SSZModel is immutable


class TestBitlist:
    """Tests for the variable-length, capacity-limited Bitlist type."""

    def test_class_creates_specialized_type(self) -> None:
        """Tests that concrete Bitlist classes have the correct limit."""

        class Bitlist8(BaseBitlist):
            LIMIT = 8

        class Bitlist16(BaseBitlist):
            LIMIT = 16

        assert Bitlist8.LIMIT == 8
        assert Bitlist16.LIMIT == 16
        assert "Bitlist8" in repr(Bitlist8)

    def test_instantiate_raw_type_raises_error(self) -> None:
        """Tests that the raw, non-specialized BaseBitlist cannot be instantiated."""
        with pytest.raises(SSZTypeError, match="must define LIMIT"):
            BaseBitlist(data=[])

    def test_instantiation_success(self) -> None:
        """Tests successful instantiation with a valid number of items."""
        instance = Bitlist8(data=[Boolean(True), Boolean(False), Boolean(1), Boolean(0)])
        assert len(instance) == 4
        expected = Bitlist8(data=[Boolean(True), Boolean(False), Boolean(True), Boolean(False)])
        assert instance == expected

    def test_instantiation_over_limit_raises_error(self) -> None:
        """Tests that providing more items than the limit during instantiation fails."""

        class Bitlist4(BaseBitlist):
            LIMIT = 4

        with pytest.raises(ValueOrValidationError):
            Bitlist4(data=[Boolean(b) for b in [True, False, True, False, True]])

    def test_pydantic_validation_accepts_valid_list(self) -> None:
        """Tests that Pydantic validation correctly accepts a valid list of booleans."""
        bits = [Boolean(True), Boolean(False), Boolean(True), Boolean(False)]
        instance = Bitlist8Model(value={"data": bits})  # type: ignore[arg-type]
        assert isinstance(instance.value, Bitlist8)
        assert len(instance.value) == 4

    @pytest.mark.parametrize(
        "invalid_value",
        [
            {"data": [Boolean(True)] * 9},  # Too long
        ],
    )
    def test_pydantic_validation_rejects_invalid_values(self, invalid_value: Any) -> None:
        """Tests that Pydantic validation rejects lists that exceed the limit."""
        with pytest.raises(ValueOrValidationError):
            Bitlist8Model(value=invalid_value)

    def test_add_with_list(self) -> None:
        """Tests concatenating a Bitlist with a regular list."""
        bitlist = Bitlist8(data=[Boolean(True), Boolean(False), Boolean(True)])
        result = bitlist + [Boolean(False), Boolean(True)]
        assert len(result) == 5
        assert list(result.data) == [
            Boolean(True),
            Boolean(False),
            Boolean(True),
            Boolean(False),
            Boolean(True),
        ]
        assert isinstance(result, Bitlist8)

    def test_add_with_bitlist(self) -> None:
        """Tests concatenating two Bitlists of the same type."""
        bitlist1 = Bitlist8(data=[Boolean(True), Boolean(False)])
        bitlist2 = Bitlist8(data=[Boolean(True), Boolean(True)])
        result = bitlist1 + bitlist2
        assert len(result) == 4
        assert list(result.data) == [
            Boolean(True),
            Boolean(False),
            Boolean(True),
            Boolean(True),
        ]
        assert isinstance(result, Bitlist8)

    def test_add_exceeding_limit_raises_error(self) -> None:
        """Tests that concatenating beyond the limit raises an error."""

        class Bitlist4(BaseBitlist):
            LIMIT = 4

        bitlist = Bitlist4(data=[Boolean(True), Boolean(False), Boolean(True)])
        with pytest.raises(ValueOrValidationError):
            bitlist + [Boolean(False), Boolean(True)]


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

        class TestBitvector(BaseBitvector):
            LENGTH = length

        bool_value = tuple(Boolean(b) for b in value)
        instance = TestBitvector(data=bool_value)

        # Test serialization
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex

        # Test deserialization
        decoded = TestBitvector.decode_bytes(encoded)
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

        class TestBitlist(BaseBitlist):
            LIMIT = limit

        bool_value = tuple(Boolean(b) for b in value)
        instance = TestBitlist(data=bool_value)

        # Test serialization
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex

        # Test deserialization
        decoded = TestBitlist.decode_bytes(encoded)
        assert decoded == instance

    def test_bitvector_decode_invalid_length(self) -> None:
        """Tests that Bitvector.decode_bytes fails for data of the wrong length."""

        class Bitvector8(BaseBitvector):
            LENGTH = 8

        with pytest.raises(SSZValueError, match="expected 1 bytes, got 2"):
            Bitvector8.decode_bytes(b"\x01\x02")  # Expects 1 byte, gets 2

    def test_bitlist_decode_invalid_data(self) -> None:
        """Tests that Bitlist.decode_bytes fails for invalid byte strings."""

        class Bitlist8(BaseBitlist):
            LIMIT = 8

        with pytest.raises(SSZSerializationError, match="cannot decode empty bytes"):
            Bitlist8.decode_bytes(b"")


class TestBitfieldSSZ:
    """Tests the SSZType interface methods for bitfields."""

    def test_bitvector_ssz_properties(self) -> None:
        class Bitvector10(BaseBitvector):
            LENGTH = 10

        assert Bitvector10.is_fixed_size() is True
        assert Bitvector10.get_byte_length() == 2  # (10+7)//8

    def test_bitlist_ssz_properties(self) -> None:
        class Bitlist10(BaseBitlist):
            LIMIT = 10

        assert Bitlist10.is_fixed_size() is False
        with pytest.raises(SSZTypeError):
            Bitlist10.get_byte_length()

    def test_bitvector_deserialize_invalid_scope(self) -> None:
        class Bitvector8(BaseBitvector):
            LENGTH = 8

        stream = io.BytesIO(b"\xff")
        with pytest.raises(SSZSerializationError, match="expected 1 bytes, got 2"):
            Bitvector8.deserialize(stream, scope=2)

    def test_bitvector_deserialize_premature_end(self) -> None:
        class Bitvector16(BaseBitvector):
            LENGTH = 16

        stream = io.BytesIO(b"\xff")  # Only 1 byte, expects 2
        with pytest.raises(SSZSerializationError, match="expected 2 bytes, got 1"):
            Bitvector16.deserialize(stream, scope=2)

    def test_bitlist_deserialize_premature_end(self) -> None:
        class Bitlist16(BaseBitlist):
            LIMIT = 16

        stream = io.BytesIO(b"\xff")  # Only 1 byte
        with pytest.raises(SSZSerializationError, match="expected 2 bytes, got 1"):
            Bitlist16.deserialize(stream, scope=2)  # Scope says to read 2

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
        class TestBitvector(BaseBitvector):
            LENGTH = length

        bool_value = tuple(Boolean(b) for b in value)
        instance = TestBitvector(data=bool_value)
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex

        # round-trip via classmethod
        decoded = TestBitvector.decode_bytes(encoded)
        assert decoded == instance

        # round-trip via stream serialize/deserialize
        stream = io.BytesIO()
        written = instance.serialize(stream)
        assert written == TestBitvector.get_byte_length()
        stream.seek(0)
        decoded2 = TestBitvector.deserialize(stream, scope=written)
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
        class TestBitlist(BaseBitlist):
            LIMIT = limit

        bool_value = tuple(Boolean(b) for b in value)
        instance = TestBitlist(data=bool_value)
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex

        # round-trip via classmethod
        decoded = TestBitlist.decode_bytes(encoded)
        assert decoded == instance

        # round-trip via stream serialize/deserialize
        stream = io.BytesIO()
        written = instance.serialize(stream)
        # variable-size, so we assert the written size matches the encoding length
        assert written == len(encoded)
        stream.seek(0)
        decoded2 = TestBitlist.deserialize(stream, scope=written)
        assert decoded2 == instance
