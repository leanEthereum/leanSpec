"""Tests for the Vector and List types."""

from typing import Any, Tuple

import pytest
from pydantic import ValidationError, create_model
from typing_extensions import Type

from lean_spec.types.boolean import Boolean
from lean_spec.types.collections import List, Vector
from lean_spec.types.container import Container
from lean_spec.types.uint import Uint8, Uint16, Uint32, Uint256


class FixedContainer(Container):
    """A simple fixed-size container for testing composite types in collections."""

    a: Uint8
    b: Uint16


class VariableContainer(Container):
    """A variable-size container for testing composite types in collections."""

    a: Uint8
    b: List[Uint16, 4]  # type: ignore


# Test data for the 'sig' vector test case
sig_test_data_list = [0] * 96
for i, v in {0: 1, 32: 2, 64: 3, 95: 0xFF}.items():
    sig_test_data_list[i] = v
sig_test_data = tuple(sig_test_data_list)


class TestVector:
    """Tests for the fixed-length, immutable Vector type."""

    def test_class_getitem_creates_specialized_type(self) -> None:
        """Tests that `Vector[T, N]` creates a new, distinct type with the correct parameters."""
        vec_type_a = Vector[Uint8, 32]  # type: ignore
        vec_type_b = Vector[Uint16, 32]  # type: ignore
        assert vec_type_a is not Vector[Uint8, 64]  # type: ignore
        assert vec_type_a is not vec_type_b
        assert vec_type_a.LENGTH == 32
        assert vec_type_a.ELEMENT_TYPE is Uint8
        assert "Vector[Uint8,32]" in repr(vec_type_a)

    def test_instantiate_raw_type_raises_error(self) -> None:
        """Tests that the raw, non-specialized Vector cannot be instantiated."""
        with pytest.raises(TypeError, match="Cannot instantiate raw Vector"):
            Vector([])

    def test_instantiation_success(self) -> None:
        """Tests successful instantiation with the correct number of valid items."""
        vec_type = Vector[Uint8, 4]  # type: ignore
        instance = vec_type([1, 2, 3, 4])
        assert len(instance) == 4
        assert instance == (Uint8(1), Uint8(2), Uint8(3), Uint8(4))

    def test_instantiation_with_wrong_length_raises_error(self) -> None:
        """Tests that providing the wrong number of items during instantiation fails."""
        vec_type = Vector[Uint8, 4]  # type: ignore
        with pytest.raises(ValueError, match="requires exactly 4 items"):
            vec_type([1, 2, 3])  # Too few
        with pytest.raises(ValueError, match="requires exactly 4 items"):
            vec_type([1, 2, 3, 4, 5])  # Too many

    def test_pydantic_validation(self) -> None:
        """Tests that Pydantic validation works for Vector types."""
        model = create_model("Model", value=(Vector[Uint8, 2], ...))  # type: ignore
        # Test valid data
        instance: Any = model(value=[10, 20])
        assert isinstance(instance.value, Vector[Uint8, 2])  # type: ignore
        assert instance.value == (Uint8(10), Uint8(20))
        # Test invalid data
        with pytest.raises(ValidationError):
            model(value=[10])  # Too short
        with pytest.raises(ValidationError):
            model(value=[10, 20, 30])  # Too long
        with pytest.raises(ValidationError):
            model(value=[10, "bad"])  # Wrong element type

    def test_vector_is_immutable(self) -> None:
        """Tests that attempting to change an item in a Vector raises a TypeError."""
        vec = Vector[Uint8, 2]([1, 2])  # type: ignore
        with pytest.raises(TypeError):
            vec[0] = 3


class TestList:
    """Tests for the variable-length, capacity-limited List type."""

    def test_class_getitem_creates_specialized_type(self) -> None:
        """Tests that `List[T, N]` creates a new, distinct type with the correct parameters."""
        list_type_a = List[Uint8, 32]  # type: ignore
        list_type_b = List[Uint16, 32]  # type: ignore
        assert list_type_a is not List[Uint8, 64]  # type: ignore
        assert list_type_a is not list_type_b
        assert list_type_a.LIMIT == 32
        assert list_type_a.ELEMENT_TYPE is Uint8
        assert "List[Uint8,32]" in repr(list_type_a)

    def test_instantiate_raw_type_raises_error(self) -> None:
        """Tests that the raw, non-specialized List cannot be instantiated."""
        with pytest.raises(TypeError, match="Cannot instantiate raw List"):
            List([])

    def test_instantiation_over_limit_raises_error(self) -> None:
        """Tests that providing more items than the limit during instantiation fails."""
        list_type = List[Uint8, 4]  # type: ignore
        with pytest.raises(ValueError, match="Too many items for List\\[Uint8,4\\]"):
            list_type([1, 2, 3, 4, 5])

    def test_pydantic_validation(self) -> None:
        """Tests that Pydantic validation works for List types."""
        model = create_model("Model", value=(List[Uint8, 4], ...))  # type: ignore
        # Test valid data
        instance: Any = model(value=[10, 20])
        assert isinstance(instance.value, List[Uint8, 4])  # type: ignore
        assert instance.value == [Uint8(10), Uint8(20)]
        # Test invalid data
        with pytest.raises(ValidationError):
            model(value=[10, 20, 30, 40, 50])  # Too long
        with pytest.raises(ValidationError):
            model(value=[10, "bad"])  # Wrong element type

    def test_append_at_limit_raises_error(self) -> None:
        """Tests that `append` fails when the list is at its capacity."""
        bl = List[Boolean, 4]([True] * 4)  # type: ignore
        with pytest.raises(ValueError, match="exceeds List\\[Boolean,4\\] limit of 4 items"):
            bl.append(False)

    def test_extend_over_limit_raises_error(self) -> None:
        """Tests that `extend` fails if the result would exceed the capacity."""
        bl = List[Boolean, 4]([True, False])  # type: ignore
        with pytest.raises(ValueError, match="exceeds List\\[Boolean,4\\] limit of 4 items"):
            bl.extend([True, False, True])


class TestVectorSerialization:
    """Tests SSZ serialization and deserialization for the Vector type."""

    @pytest.mark.parametrize(
        "vector_type, value, expected_hex",
        [
            (Vector[Uint16, 2], (0x4567, 0x0123), "67452301"),  # type: ignore
            (Vector[Uint8, 4], (1, 2, 3, 4), "01020304"),  # type: ignore
            (
                Vector[Uint8, 48],  # type: ignore
                tuple(range(48)),
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f",
            ),
            (
                Vector[Uint8, 96],  # type: ignore
                sig_test_data,
                "0100000000000000000000000000000000000000000000000000000000000000"
                "0200000000000000000000000000000000000000000000000000000000000000"
                "03000000000000000000000000000000000000000000000000000000000000ff",
            ),
            (
                Vector[FixedContainer, 2],  # type: ignore
                (FixedContainer(a=Uint8(1), b=Uint16(2)), FixedContainer(a=Uint8(3), b=Uint16(4))),
                "010200030400",  # 010200 for first element, 030400 for second
            ),
        ],
    )
    def test_fixed_size_element_vector_serialization(
        self, vector_type: Type[Vector], value: Tuple[Any, ...], expected_hex: str
    ) -> None:
        """Tests the serialization of vectors with fixed-size elements."""
        instance = vector_type(value)
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex
        decoded = vector_type.decode_bytes(encoded)
        assert decoded == instance

    def test_variable_size_element_vector_serialization(self) -> None:
        """Tests the serialization of vectors with variable-size elements."""
        vec_type = Vector[VariableContainer, 2]  # type: ignore
        list_type = List[Uint16, 4]  # type: ignore

        # The inner list (`b`) now serializes to a packed representation, changing the total size
        val1 = VariableContainer(
            a=Uint8(1), b=list_type([Uint16(10), Uint16(20)])
        )  # Serialized size: 1 + 4 + (2*2) = 9 bytes
        val2 = VariableContainer(
            a=Uint8(2), b=list_type([Uint16(30)])
        )  # Serialized size: 1 + 4 + (1*2) = 7 bytes
        instance = vec_type([val1, val2])

        expected_hex = (
            "0800000011000000"  # Offsets: val1 starts at 8, val2 starts at 17 (8+9)
            "01050000000a001400"  # val1 data: a=1, offset=5, b_data=[10,20]
            "02050000001e00"  # val2 data: a=2, offset=5, b_data=[30]
        )

        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex
        decoded = vec_type.decode_bytes(encoded)
        assert decoded == instance


class TestListSerialization:
    """Tests SSZ serialization and deserialization for the List type."""

    @pytest.mark.parametrize(
        "list_type, value, expected_hex",
        [
            # Lists of fixed-size elements are concatenated, matching the reference spec
            (List[Uint16, 32], (0xAABB, 0xC0AD, 0xEEFF), "bbaaadc0ffee"),  # type: ignore
            (List[Uint8, 10], (), ""),  # type: ignore
            (List[Uint8, 10], (0, 1, 2, 3, 4, 5, 6), "00010203040506"),  # type: ignore
            (List[Uint32, 128], (0xAABB, 0xC0AD, 0xEEFF), "bbaa0000adc00000ffee0000"),  # type: ignore
            (
                List[Uint256, 32],  # type: ignore
                (0xAABB, 0xC0AD, 0xEEFF),
                (
                    "bbaa000000000000000000000000000000000000000000000000000000000000"
                    "adc0000000000000000000000000000000000000000000000000000000000000"
                    "ffee000000000000000000000000000000000000000000000000000000000000"
                ),
            ),
            (
                List[Uint256, 128],  # type: ignore
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
        list_type = List[VariableContainer, 2]  # type: ignore
        element_list_type = List[Uint16, 4]  # type: ignore

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
