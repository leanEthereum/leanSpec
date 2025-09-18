"""Tests for the SSZVector and List types."""

from typing import Any, Tuple

import pytest
from pydantic import ValidationError, create_model
from typing_extensions import Type

from lean_spec.types.boolean import Boolean
from lean_spec.types.collections import List, SSZVector
from lean_spec.types.container import Container
from lean_spec.types.uint import Uint8, Uint16, Uint32, Uint256


# Define some List types that are needed for Container definitions
class Uint16List4(List):
    """A list with up to 4 Uint16 values."""

    ELEMENT_TYPE = Uint16
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
class Uint16Vector2(SSZVector):
    """A vector of exactly 2 Uint16 values."""

    ELEMENT_TYPE = Uint16
    LENGTH = 2


class Uint8Vector4(SSZVector):
    """A vector of exactly 4 Uint8 values."""

    ELEMENT_TYPE = Uint8
    LENGTH = 4


class Uint8Vector48(SSZVector):
    """A vector of exactly 48 Uint8 values."""

    ELEMENT_TYPE = Uint8
    LENGTH = 48


class Uint8Vector96(SSZVector):
    """A vector of exactly 96 Uint8 values."""

    ELEMENT_TYPE = Uint8
    LENGTH = 96


class FixedContainerVector2(SSZVector):
    """A vector of exactly 2 FixedContainer values."""

    ELEMENT_TYPE = FixedContainer
    LENGTH = 2


class VariableContainerVector2(SSZVector):
    """A vector of exactly 2 VariableContainer values."""

    ELEMENT_TYPE = VariableContainer
    LENGTH = 2


# Define explicit List types for testing
class Uint16List32(List):
    """A list with up to 32 Uint16 values."""

    ELEMENT_TYPE = Uint16
    LIMIT = 32


class Uint8List10(List):
    """A list with up to 10 Uint8 values."""

    ELEMENT_TYPE = Uint8
    LIMIT = 10


class Uint32List128(List):
    """A list with up to 128 Uint32 values."""

    ELEMENT_TYPE = Uint32
    LIMIT = 128


class Uint256List32(List):
    """A list with up to 32 Uint256 values."""

    ELEMENT_TYPE = Uint256
    LIMIT = 32


class Uint256List128(List):
    """A list with up to 128 Uint256 values."""

    ELEMENT_TYPE = Uint256
    LIMIT = 128


class VariableContainerList2(List):
    """A list with up to 2 VariableContainer values."""

    ELEMENT_TYPE = VariableContainer
    LIMIT = 2


# Additional SSZVector classes for tests
class Uint8Vector32(SSZVector):
    """A vector of exactly 32 Uint8 values."""

    ELEMENT_TYPE = Uint8
    LENGTH = 32


class Uint16Vector32(SSZVector):
    """A vector of exactly 32 Uint16 values."""

    ELEMENT_TYPE = Uint16
    LENGTH = 32


class Uint8Vector64(SSZVector):
    """A vector of exactly 64 Uint8 values."""

    ELEMENT_TYPE = Uint8
    LENGTH = 64


class Uint8Vector2(SSZVector):
    """A vector of exactly 2 Uint8 values."""

    ELEMENT_TYPE = Uint8
    LENGTH = 2


# Additional List classes for tests
class Uint8List32(List):
    """A list with up to 32 Uint8 values."""

    ELEMENT_TYPE = Uint8
    LIMIT = 32


class Uint8List64(List):
    """A list with up to 64 Uint8 values."""

    ELEMENT_TYPE = Uint8
    LIMIT = 64


class Uint8List4(List):
    """A list with up to 4 Uint8 values."""

    ELEMENT_TYPE = Uint8
    LIMIT = 4


class BooleanList4(List):
    """A list with up to 4 Boolean values."""

    ELEMENT_TYPE = Boolean
    LIMIT = 4


# Test data for the 'sig' vector test case
sig_test_data_list = [0] * 96
for i, v in {0: 1, 32: 2, 64: 3, 95: 0xFF}.items():
    sig_test_data_list[i] = v
sig_test_data = tuple(sig_test_data_list)


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
        instance = vec_type(data=[1, 2, 3, 4])
        assert len(instance) == 4
        assert instance.data == (Uint8(1), Uint8(2), Uint8(3), Uint8(4))

    def test_instantiation_with_wrong_length_raises_error(self) -> None:
        """Tests that providing the wrong number of items during instantiation fails."""
        vec_type = Uint8Vector4
        with pytest.raises(ValueError, match="requires exactly 4 items"):
            vec_type(data=[1, 2, 3])  # Too few
        with pytest.raises(ValueError, match="requires exactly 4 items"):
            vec_type(data=[1, 2, 3, 4, 5])  # Too many

    def test_pydantic_validation(self) -> None:
        """Tests that Pydantic validation works for SSZVector types."""
        model = create_model("Model", value=(Uint8Vector2, ...))
        # Test valid data
        instance: Any = model(value={"data": [10, 20]})
        assert isinstance(instance.value, Uint8Vector2)
        assert instance.value.data == (Uint8(10), Uint8(20))
        # Test invalid data
        with pytest.raises(ValidationError):
            model(value={"data": [10]})  # Too short
        with pytest.raises(ValidationError):
            model(value={"data": [10, 20, 30]})  # Too long
        with pytest.raises(TypeError):
            model(value={"data": [10, "bad"]})  # Wrong element type

    def test_vector_is_immutable(self) -> None:
        """Tests that attempting to change an item in an SSZVector raises a TypeError."""
        vec = Uint8Vector2(data=[1, 2])
        with pytest.raises(TypeError):
            vec.data[0] = 3  # type: ignore


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
        """Tests that the raw, non-specialized List cannot be instantiated."""
        with pytest.raises(TypeError, match="Cannot instantiate raw List"):
            List([])

    def test_instantiation_over_limit_raises_error(self) -> None:
        """Tests that providing more items than the limit during instantiation fails."""
        list_type = Uint8List4
        with pytest.raises(ValueError, match="Too many items for Uint8List4"):
            list_type([1, 2, 3, 4, 5])

    def test_pydantic_validation(self) -> None:
        """Tests that Pydantic validation works for List types."""
        model = create_model("Model", value=(Uint8List4, ...))
        # Test valid data
        instance: Any = model(value=[10, 20])
        assert isinstance(instance.value, Uint8List4)
        assert instance.value == [Uint8(10), Uint8(20)]
        # Test invalid data
        with pytest.raises(ValidationError):
            model(value=[10, 20, 30, 40, 50])  # Too long
        with pytest.raises(ValidationError):
            model(value=[10, "bad"])  # Wrong element type

    def test_append_at_limit_raises_error(self) -> None:
        """Tests that `append` fails when the list is at its capacity."""
        bl = BooleanList4([True] * 4)
        with pytest.raises(ValueError, match="exceeds BooleanList4 limit of 4 items"):
            bl.append(False)

    def test_extend_over_limit_raises_error(self) -> None:
        """Tests that `extend` fails if the result would exceed the capacity."""
        bl = BooleanList4([True, False])
        with pytest.raises(ValueError, match="exceeds BooleanList4 limit of 4 items"):
            bl.extend([True, False, True])


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
            a=Uint8(1), b=list_type([Uint16(10), Uint16(20)])
        )  # Serialized size: 1 + 4 + (2*2) = 9 bytes
        val2 = VariableContainer(
            a=Uint8(2), b=list_type([Uint16(30)])
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


class TestListSerialization:
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
                Uint256List32,
                (0xAABB, 0xC0AD, 0xEEFF),
                (
                    "bbaa000000000000000000000000000000000000000000000000000000000000"
                    "adc0000000000000000000000000000000000000000000000000000000000000"
                    "ffee000000000000000000000000000000000000000000000000000000000000"
                ),
            ),
            (
                Uint256List128,
                tuple(range(1, 20)),
                "".join(i.to_bytes(32, "little").hex() for i in range(1, 20)),
            ),
        ],
    )
    def test_fixed_size_element_list_serialization(
        self, list_type: Type[List], value: Tuple[Any, ...], expected_hex: str
    ) -> None:
        """Tests the serialization of lists with fixed-size elements."""
        instance = list_type(value)
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex
        decoded = list_type.decode_bytes(encoded)
        assert decoded == instance

    def test_variable_size_element_list_serialization(self) -> None:
        """Tests the serialization of lists with variable-size elements."""
        list_type = VariableContainerList2
        element_list_type = Uint16List4

        val1 = VariableContainer(
            a=Uint8(1), b=element_list_type([Uint16(10)])
        )  # Serialized size: 1 + 4 + 2 = 7 bytes
        val2 = VariableContainer(
            a=Uint8(2), b=element_list_type([Uint16(30), Uint16(40)])
        )  # Serialized size: 1 + 4 + 4 = 9 bytes
        instance = list_type([val1, val2])

        expected_hex = (
            "080000000f000000"  # Offsets: val1 starts at 8, val2 starts at 15 (8+7)
            "01050000000a00"  # val1 data
            "02050000001e002800"  # val2 data
        )

        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex
        decoded = list_type.decode_bytes(encoded)
        assert decoded == instance
