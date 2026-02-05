"""Tests for the SSZVector and List types."""

from typing import Any, Tuple

import pytest
from pydantic import BaseModel, ValidationError
from typing_extensions import Type

from lean_spec.subspecs.koalabear import Fp
from lean_spec.types.boolean import Boolean
from lean_spec.types.byte_arrays import Bytes32
from lean_spec.types.collections import SSZList, SSZVector
from lean_spec.types.container import Container
from lean_spec.types.exceptions import SSZTypeError, SSZValueError
from lean_spec.types.uint import Uint8, Uint16, Uint32

# Type alias for errors that can be SSZValueError or wrapped in ValidationError
ValueOrValidationError = (SSZValueError, ValidationError)


# Define some List types that are needed for Container definitions
class Uint16List4(SSZList[Uint16]):
    """A list with up to 4 Uint16 values."""

    LIMIT = 4


class FixedContainer(Container):
    """A simple fixed-size container for testing composite types in collections."""

    a: Uint8
    b: Uint16


class VariableContainer(Container):
    """A variable-size container for testing composite types in collections."""

    a: Uint8
    b: Uint16List4


# Define explicit SSZVector types for testing
class Uint16Vector2(SSZVector[Uint16]):
    """A vector of exactly 2 Uint16 values."""

    LENGTH = 2


class Uint8Vector4(SSZVector[Uint8]):
    """A vector of exactly 4 Uint8 values."""

    LENGTH = 4


class Uint8Vector48(SSZVector[Uint8]):
    """A vector of exactly 48 Uint8 values."""

    LENGTH = 48


class Uint8Vector96(SSZVector[Uint8]):
    """A vector of exactly 96 Uint8 values."""

    LENGTH = 96


class FixedContainerVector2(SSZVector[FixedContainer]):
    """A vector of exactly 2 FixedContainer values."""

    LENGTH = 2


class VariableContainerVector2(SSZVector[VariableContainer]):
    """A vector of exactly 2 VariableContainer values."""

    LENGTH = 2


# Define explicit List types for testing
class Uint16List32(SSZList[Uint16]):
    """A list with up to 32 Uint16 values."""

    LIMIT = 32


class Uint8List10(SSZList[Uint8]):
    """A list with up to 10 Uint8 values."""

    LIMIT = 10


class Uint32List128(SSZList[Uint32]):
    """A list with up to 128 Uint32 values."""

    LIMIT = 128


class Bytes32List32(SSZList[Bytes32]):
    """A list with up to 32 Bytes32 values."""

    LIMIT = 32


class Bytes32List128(SSZList[Bytes32]):
    """A list with up to 128 Bytes32 values."""

    LIMIT = 128


class VariableContainerList2(SSZList[VariableContainer]):
    """A list with up to 2 VariableContainer values."""

    LIMIT = 2


# Additional SSZVector classes for tests
class Uint8Vector32(SSZVector[Uint8]):
    """A vector of exactly 32 Uint8 values."""

    LENGTH = 32


class Uint16Vector32(SSZVector[Uint16]):
    """A vector of exactly 32 Uint16 values."""

    LENGTH = 32


class Uint8Vector64(SSZVector[Uint8]):
    """A vector of exactly 64 Uint8 values."""

    LENGTH = 64


class Uint8Vector2(SSZVector[Uint8]):
    """A vector of exactly 2 Uint8 values."""

    LENGTH = 2


class FpVector8(SSZVector[Fp]):
    """A vector of exactly 8 Fp values."""

    LENGTH = 8


# Additional List classes for tests
class Uint8List32(SSZList[Uint8]):
    """A list with up to 32 Uint8 values."""

    LIMIT = 32


class Uint8List64(SSZList[Uint8]):
    """A list with up to 64 Uint8 values."""

    LIMIT = 64


class Uint8List4(SSZList[Uint8]):
    """A list with up to 4 Uint8 values."""

    LIMIT = 4


class BooleanList4(SSZList[Boolean]):
    """A list with up to 4 Boolean values."""

    LIMIT = 4


class FpList8(SSZList[Fp]):
    """A list with up to 8 Fp values."""

    LIMIT = 8


# Test data for the 'sig' vector test case
sig_test_data_list = [0] * 96
for i, v in {0: 1, 32: 2, 64: 3, 95: 0xFF}.items():
    sig_test_data_list[i] = v
sig_test_data = tuple(sig_test_data_list)


class Uint8Vector2Model(BaseModel):
    """Model for testing Pydantic validation of Uint8Vector2."""

    value: Uint8Vector2


class TestSSZVector:
    """Tests for the fixed-length, immutable SSZVector type."""

    def test_class_getitem_creates_specialized_type(self) -> None:
        """Tests that explicit SSZVector classes have the correct parameters."""
        vec_type_a = Uint8Vector32
        vec_type_b = Uint16Vector32
        assert vec_type_a is not Uint8Vector64  # type: ignore[comparison-overlap]
        assert vec_type_a is not vec_type_b  # type: ignore[comparison-overlap]
        assert vec_type_a.LENGTH == 32
        assert vec_type_a.ELEMENT_TYPE is Uint8
        assert "Uint8Vector32" in repr(vec_type_a)

    def test_instantiate_raw_type_raises_error(self) -> None:
        """Tests that the raw, non-specialized SSZVector cannot be instantiated."""
        with pytest.raises(TypeError, match="BaseModel.__init__\\(\\) takes 1 positional argument"):
            SSZVector([])  # type: ignore[misc]

    def test_instantiation_success(self) -> None:
        """Tests successful instantiation with the correct number of valid items."""
        vec_type = Uint8Vector4
        instance = vec_type(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4)])
        assert len(instance) == 4
        assert list(instance) == [Uint8(1), Uint8(2), Uint8(3), Uint8(4)]

    def test_instantiation_with_wrong_length_raises_error(self) -> None:
        """Tests that providing the wrong number of items during instantiation fails."""
        vec_type = Uint8Vector4
        with pytest.raises(ValueOrValidationError):
            vec_type(data=[Uint8(1), Uint8(2), Uint8(3)])  # Too few
        with pytest.raises(ValueOrValidationError):
            vec_type(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4), Uint8(5)])  # Too many

    def test_pydantic_validation(self) -> None:
        """Tests that Pydantic validation works for SSZVector types."""
        # Test valid data - Pydantic coerces dict to Uint8Vector2
        instance = Uint8Vector2Model(value={"data": [10, 20]})  # type: ignore[arg-type]
        assert isinstance(instance.value, Uint8Vector2)
        assert list(instance.value) == [Uint8(10), Uint8(20)]
        # Test invalid data
        with pytest.raises(ValueOrValidationError):
            Uint8Vector2Model(value={"data": [10]})  # type: ignore[arg-type]
        with pytest.raises(ValueOrValidationError):
            Uint8Vector2Model(value={"data": [10, 20, 30]})  # type: ignore[arg-type]
        with pytest.raises(SSZTypeError):
            Uint8Vector2Model(value={"data": [10, "bad"]})  # type: ignore[arg-type]

    def test_vector_is_immutable(self) -> None:
        """Tests that attempting to change an item in an SSZVector raises a TypeError."""
        vec = Uint8Vector2(data=[Uint8(1), Uint8(2)])
        with pytest.raises(TypeError):
            vec[0] = 3  # type: ignore[index]  # Should fail because SSZModel is immutable


class Uint8List4Model(BaseModel):
    """Model for testing Pydantic validation of Uint8List4."""

    value: Uint8List4


class TestList:
    """Tests for the variable-length, capacity-limited List type."""

    def test_class_getitem_creates_specialized_type(self) -> None:
        """Tests that explicit List classes have the correct parameters."""
        list_type_a = Uint8List32
        list_type_b = Uint16List32
        assert list_type_a is not Uint8List64  # type: ignore[comparison-overlap]
        assert list_type_a is not list_type_b  # type: ignore[comparison-overlap]
        assert list_type_a.LIMIT == 32
        assert list_type_a.ELEMENT_TYPE is Uint8
        assert "Uint8List32" in repr(list_type_a)

    def test_instantiate_raw_type_raises_error(self) -> None:
        """Tests that the raw, non-specialized SSZList cannot be instantiated."""
        with pytest.raises(SSZTypeError, match="must define ELEMENT_TYPE and LIMIT"):
            SSZList(data=[])

    def test_instantiation_over_limit_raises_error(self) -> None:
        """Tests that providing more items than the limit during instantiation fails."""
        list_type = Uint8List4
        with pytest.raises(ValueOrValidationError):
            list_type(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4), Uint8(5)])

    def test_pydantic_validation(self) -> None:
        """Tests that Pydantic validation works for List types."""
        # Test valid data
        instance = Uint8List4Model(value=Uint8List4(data=[Uint8(10), Uint8(20)]))
        assert isinstance(instance.value, Uint8List4)
        assert list(instance.value) == [Uint8(10), Uint8(20)]
        # Test invalid data - list too long
        with pytest.raises(ValueOrValidationError):
            Uint8List4Model(
                value=Uint8List4(data=[Uint8(10), Uint8(20), Uint8(30), Uint8(40), Uint8(50)])
            )

    def test_append_at_limit_raises_error(self) -> None:
        """Tests that creating a list at limit +1 fails during construction."""
        with pytest.raises(ValueOrValidationError):
            BooleanList4(data=[Boolean(True)] * 5)

    def test_extend_over_limit_raises_error(self) -> None:
        """Tests that creating a list over the limit fails during construction."""
        with pytest.raises(ValueOrValidationError):
            BooleanList4(
                data=[Boolean(True), Boolean(False), Boolean(True), Boolean(False), Boolean(True)]
            )

    def test_add_with_list(self) -> None:
        """Tests concatenating an SSZList with a regular list."""
        list1 = Uint8List10(data=[Uint8(1), Uint8(2), Uint8(3)])
        result = list1 + [4, 5]
        assert list(result) == [Uint8(1), Uint8(2), Uint8(3), Uint8(4), Uint8(5)]
        assert isinstance(result, Uint8List10)

    def test_add_with_sszlist(self) -> None:
        """Tests concatenating two SSZLists of the same type."""
        list1 = Uint8List10(data=[Uint8(1), Uint8(2)])
        list2 = Uint8List10(data=[Uint8(3), Uint8(4)])
        result = list1 + list2
        assert list(result) == [Uint8(1), Uint8(2), Uint8(3), Uint8(4)]
        assert isinstance(result, Uint8List10)

    def test_add_exceeding_limit_raises_error(self) -> None:
        """Tests that concatenating beyond the limit raises an error."""
        list1 = Uint8List4(data=[Uint8(1), Uint8(2), Uint8(3)])
        with pytest.raises(ValueOrValidationError):
            list1 + [4, 5]


class TestSSZVectorSerialization:
    """Tests SSZ serialization and deserialization for the SSZVector type."""

    @pytest.mark.parametrize(
        "vector_type, value, expected_hex",
        [
            (Uint16Vector2, (0x4567, 0x0123), "67452301"),
            (Uint8Vector4, (1, 2, 3, 4), "01020304"),
            (
                Uint8Vector48,
                tuple(range(48)),
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f",
            ),
            (
                Uint8Vector96,
                sig_test_data,
                "0100000000000000000000000000000000000000000000000000000000000000"
                "0200000000000000000000000000000000000000000000000000000000000000"
                "03000000000000000000000000000000000000000000000000000000000000ff",
            ),
            (
                FixedContainerVector2,
                (FixedContainer(a=Uint8(1), b=Uint16(2)), FixedContainer(a=Uint8(3), b=Uint16(4))),
                "010200030400",  # 010200 for first element, 030400 for second
            ),
            (
                FpVector8,
                (10, 20, 30, 40, 50, 60, 70, 80),
                "0a000000140000001e00000028000000320000003c0000004600000050000000",
            ),
        ],
    )
    def test_fixed_size_element_vector_serialization(
        self, vector_type: Type[SSZVector], value: Tuple[Any, ...], expected_hex: str
    ) -> None:
        """Tests the serialization of vectors with fixed-size elements."""
        instance = vector_type(data=value)
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex
        decoded = vector_type.decode_bytes(encoded)
        assert decoded == instance

    def test_variable_size_element_vector_serialization(self) -> None:
        """Tests the serialization of vectors with variable-size elements."""
        list_type = Uint16List4

        # The inner list (`b`) now serializes to a packed representation, changing the total size
        val1 = VariableContainer(
            a=Uint8(1), b=list_type(data=[Uint16(10), Uint16(20)])
        )  # Serialized size: 1 + 4 + (2*2) = 9 bytes
        val2 = VariableContainer(
            a=Uint8(2), b=list_type(data=[Uint16(30)])
        )  # Serialized size: 1 + 4 + (1*2) = 7 bytes
        instance = VariableContainerVector2(data=[val1, val2])

        expected_hex = (
            "0800000011000000"  # Offsets: val1 starts at 8, val2 starts at 17 (8+9)
            "01050000000a001400"  # val1 data: a=1, offset=5, b_data=[10,20]
            "02050000001e00"  # val2 data: a=2, offset=5, b_data=[30]
        )

        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex
        decoded = VariableContainerVector2.decode_bytes(encoded)
        assert decoded == instance


class TestSSZListSerialization:
    """Tests SSZ serialization and deserialization for the List type."""

    @pytest.mark.parametrize(
        "list_type, value, expected_hex",
        [
            # Lists of fixed-size elements are concatenated, matching the reference spec
            (Uint16List32, (0xAABB, 0xC0AD, 0xEEFF), "bbaaadc0ffee"),
            (Uint8List10, (), ""),
            (Uint8List10, (0, 1, 2, 3, 4, 5, 6), "00010203040506"),
            (Uint32List128, (0xAABB, 0xC0AD, 0xEEFF), "bbaa0000adc00000ffee0000"),
            (
                Bytes32List32,
                (
                    b"\xbb\xaa" + b"\x00" * 30,
                    b"\xad\xc0" + b"\x00" * 30,
                    b"\xff\xee" + b"\x00" * 30,
                ),
                (
                    "bbaa000000000000000000000000000000000000000000000000000000000000"
                    "adc0000000000000000000000000000000000000000000000000000000000000"
                    "ffee000000000000000000000000000000000000000000000000000000000000"
                ),
            ),
            (
                Bytes32List128,
                tuple(i.to_bytes(32, "little") for i in range(1, 20)),
                "".join(i.to_bytes(32, "little").hex() for i in range(1, 20)),
            ),
            (
                FpList8,
                (10, 20, 30),
                "0a000000140000001e000000",
            ),
        ],
    )
    def test_fixed_size_element_list_serialization(
        self, list_type: Type[SSZList], value: Tuple[Any, ...], expected_hex: str
    ) -> None:
        """Tests the serialization of lists with fixed-size elements."""
        instance = list_type(data=value)
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex
        decoded = list_type.decode_bytes(encoded)
        assert decoded == instance

    def test_variable_size_element_list_serialization(self) -> None:
        """Tests the serialization of lists with variable-size elements."""
        list_type = VariableContainerList2
        element_list_type = Uint16List4

        val1 = VariableContainer(
            a=Uint8(1), b=element_list_type(data=[Uint16(10)])
        )  # Serialized size: 1 + 4 + 2 = 7 bytes
        val2 = VariableContainer(
            a=Uint8(2), b=element_list_type(data=[Uint16(30), Uint16(40)])
        )  # Serialized size: 1 + 4 + 4 = 9 bytes
        instance = list_type(data=[val1, val2])

        expected_hex = (
            "080000000f000000"  # Offsets: val1 starts at 8, val2 starts at 15 (8+7)
            "01050000000a00"  # val1 data
            "02050000001e002800"  # val2 data
        )

        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex
        decoded = list_type.decode_bytes(encoded)
        assert decoded == instance
