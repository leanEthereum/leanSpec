"""Tests for the SSZVector and List types."""

from typing import Any, cast

import pytest
from pydantic import BaseModel, ValidationError

from lean_spec.subspecs.koalabear import Fp
from lean_spec.types import Bytes32, Uint8, Uint16, Uint32
from lean_spec.types.boolean import Boolean
from lean_spec.types.collections import (
    SSZList,
    SSZVector,
    _extract_element_type_from_generic,
    _serialize_ssz_elements_to_json,
    _validate_offsets,
)
from lean_spec.types.container import Container
from lean_spec.types.exceptions import SSZSerializationError, SSZTypeError, SSZValueError

# Type alias for errors that can be SSZValueError or wrapped in ValidationError
ValueOrValidationError = (SSZValueError, ValidationError)
TypeOrValidationError = (SSZTypeError, ValidationError)


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


class TestCollectionHelpers:
    """Tests for SSZ collection helper functions."""

    def test_extract_element_type_from_generic_returns_element_type(self) -> None:
        """Tests extracting the element type from Pydantic generic metadata."""
        assert _extract_element_type_from_generic(Uint16Vector2, SSZVector) is Uint16

    def test_extract_element_type_from_generic_returns_none_without_metadata(self) -> None:
        """Tests that classes without matching generic metadata return None."""

        class PlainClass:
            pass

        assert _extract_element_type_from_generic(PlainClass, SSZVector) is None

    def test_serialize_ssz_elements_to_json_handles_supported_types(self) -> None:
        """Tests JSON serialization for bytes, field elements, and plain values."""
        marker = object()
        result = _serialize_ssz_elements_to_json([Bytes32.zero(), Fp(7), marker])

        assert result[0] == "0x" + ("00" * 32)
        assert result[1] == 7
        assert result[2] is marker

    def test_validate_offsets_accepts_empty_and_monotonic_offsets(self) -> None:
        """Tests offset validation success cases."""
        _validate_offsets([], scope=0, type_name="TestType")
        _validate_offsets([4, 8, 12], scope=12, type_name="TestType")

    def test_validate_offsets_rejects_non_monotonic_offsets(self) -> None:
        """Tests offset validation rejects decreasing offsets."""
        with pytest.raises(SSZSerializationError, match="offsets not monotonically increasing"):
            _validate_offsets([4, 3], scope=4, type_name="TestType")

    def test_validate_offsets_rejects_final_offset_beyond_scope(self) -> None:
        """Tests offset validation rejects a final offset beyond scope."""
        with pytest.raises(SSZSerializationError, match="final offset 8 exceeds scope 7"):
            _validate_offsets([4, 8], scope=7, type_name="TestType")


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

    def test_init_subclass_infers_element_type_from_generic(self) -> None:
        """Tests generic subclasses infer their element type automatically."""

        class LocalVector(SSZVector[Uint16]):
            LENGTH = 1

        assert LocalVector.ELEMENT_TYPE is Uint16

    def test_init_subclass_preserves_explicit_element_type(self) -> None:
        """Tests an explicit ELEMENT_TYPE is not overwritten by generic inference."""

        class LocalVector(SSZVector[Uint8]):
            ELEMENT_TYPE = Uint16
            LENGTH = 1

        assert LocalVector.ELEMENT_TYPE is Uint16

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

    def test_instantiation_from_iterator_coerces_values(self) -> None:
        """Tests iterator input is consumed and elements are coerced to ELEMENT_TYPE."""
        instance = Uint8Vector4(data=cast(Any, (value for value in range(1, 5))))

        assert tuple(instance) == (Uint8(1), Uint8(2), Uint8(3), Uint8(4))

    def test_instantiation_without_length_raises_error(self) -> None:
        """Tests misconfigured vector subclasses fail validation."""

        class MissingLengthVector(SSZVector[Uint8]):
            pass

        with pytest.raises(TypeOrValidationError, match="must define ELEMENT_TYPE and LENGTH"):
            MissingLengthVector(data=cast(Any, [1]))

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

    def test_variable_size_vector_has_no_fixed_byte_length(self) -> None:
        """Tests variable-size vectors do not expose a fixed byte length."""
        with pytest.raises(SSZTypeError, match="variable-size vector has no fixed byte length"):
            VariableContainerVector2.get_byte_length()

    def test_elements_returns_copy_and_slice_returns_sequence(self) -> None:
        """Tests vector convenience accessors return safe views of the data."""
        vec = Uint8Vector4(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4)])

        elements = vec.elements
        elements.append(Uint8(9))

        assert elements == [Uint8(1), Uint8(2), Uint8(3), Uint8(4), Uint8(9)]
        assert list(vec) == [Uint8(1), Uint8(2), Uint8(3), Uint8(4)]
        assert vec[1:3] == (Uint8(2), Uint8(3))

    def test_model_dump_json_serializes_vector_elements(self) -> None:
        """Tests vector field serializers are used in JSON mode."""
        instance = FpVector8(data=[Fp(1), Fp(2), Fp(3), Fp(4), Fp(5), Fp(6), Fp(7), Fp(8)])

        assert instance.model_dump(mode="json")["data"] == [1, 2, 3, 4, 5, 6, 7, 8]


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

    def test_init_subclass_infers_element_type_from_generic(self) -> None:
        """Tests generic list subclasses infer their element type automatically."""

        class LocalList(SSZList[Uint16]):
            LIMIT = 2

        assert LocalList.ELEMENT_TYPE is Uint16

    def test_instantiate_raw_type_raises_error(self) -> None:
        """Tests that the raw, non-specialized SSZList cannot be instantiated."""
        with pytest.raises(SSZTypeError, match="must define ELEMENT_TYPE and LIMIT"):
            SSZList(data=[])

    def test_instantiation_without_limit_raises_error(self) -> None:
        """Tests misconfigured list subclasses fail validation."""

        class MissingLimitList(SSZList[Uint8]):
            pass

        with pytest.raises(TypeOrValidationError, match="must define ELEMENT_TYPE and LIMIT"):
            MissingLimitList(data=cast(Any, [1]))

    def test_instantiation_over_limit_raises_error(self) -> None:
        """Tests that providing more items than the limit during instantiation fails."""
        list_type = Uint8List4
        with pytest.raises(ValueOrValidationError):
            list_type(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4), Uint8(5)])

    def test_instantiation_from_iterator_coerces_values(self) -> None:
        """Tests iterator input is materialized and elements are coerced."""
        instance = Uint8List4(data=cast(Any, (value for value in range(3))))

        assert list(instance) == [Uint8(0), Uint8(1), Uint8(2)]

    def test_non_iterable_input_raises_error(self) -> None:
        """Tests non-iterable inputs are rejected."""
        with pytest.raises(TypeOrValidationError, match="Expected iterable"):
            Uint8List4(data=5)  # type: ignore[arg-type]

    def test_invalid_element_type_raises_descriptive_error(self) -> None:
        """Tests failed element coercion produces a descriptive error."""
        with pytest.raises(TypeOrValidationError, match="Expected Uint8, got"):
            Uint8List4(data=[1, "bad"])  # type: ignore[list-item]

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

    def test_add_with_tuple(self) -> None:
        """Tests concatenating an SSZList with a tuple."""
        list1 = Uint8List10(data=[Uint8(1), Uint8(2)])
        result = list1 + (3, 4)

        assert list(result) == [Uint8(1), Uint8(2), Uint8(3), Uint8(4)]
        assert isinstance(result, Uint8List10)

    def test_add_with_unsupported_type_returns_not_implemented(self) -> None:
        """Tests unsupported operands return NotImplemented from __add__."""
        list1 = Uint8List10(data=[Uint8(1), Uint8(2)])

        assert list1.__add__(object()) is NotImplemented

    def test_add_exceeding_limit_raises_error(self) -> None:
        """Tests that concatenating beyond the limit raises an error."""
        list1 = Uint8List4(data=[Uint8(1), Uint8(2), Uint8(3)])
        with pytest.raises(ValueOrValidationError):
            list1 + [4, 5]

    def test_elements_returns_copy(self) -> None:
        """Tests the elements property returns a copy of the underlying data."""
        instance = Uint8List4(data=[Uint8(1), Uint8(2), Uint8(3)])

        elements = instance.elements
        elements.append(Uint8(9))

        assert elements == [Uint8(1), Uint8(2), Uint8(3), Uint8(9)]
        assert list(instance) == [Uint8(1), Uint8(2), Uint8(3)]

    def test_list_is_never_fixed_size(self) -> None:
        """Tests SSZList is always variable-size."""
        assert Uint8List4.is_fixed_size() is False

    def test_get_byte_length_raises_for_variable_size_list(self) -> None:
        """Tests lists do not expose a fixed byte length."""
        with pytest.raises(SSZTypeError, match="variable-size list has no fixed byte length"):
            Uint8List4.get_byte_length()

    def test_model_dump_json_serializes_list_elements(self) -> None:
        """Tests list field serializers are used in JSON mode."""
        instance = Bytes32List32(data=[Bytes32.zero()])

        assert instance.model_dump(mode="json")["data"] == ["0x" + ("00" * 32)]


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
        self, vector_type: type[SSZVector], value: tuple[Any, ...], expected_hex: str
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

    def test_variable_size_vector_deserialization_rejects_invalid_first_offset(self) -> None:
        """Tests variable-size vectors reject an invalid initial offset."""
        with pytest.raises(SSZSerializationError, match="invalid offset 4, expected 8"):
            VariableContainerVector2.decode_bytes(b"\x04\x00\x00\x00")


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
        self, list_type: type[SSZList], value: tuple[Any, ...], expected_hex: str
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

    def test_fixed_size_list_deserialization_rejects_invalid_scope(self) -> None:
        """Tests fixed-size lists reject scopes not divisible by element size."""
        with pytest.raises(SSZSerializationError, match="scope 1 not divisible by element size 2"):
            Uint16List4.decode_bytes(b"\x01")

    def test_variable_size_list_deserialization_accepts_empty_scope(self) -> None:
        """Tests variable-size lists decode an empty payload as an empty list."""
        decoded = VariableContainerList2.decode_bytes(b"")

        assert decoded == VariableContainerList2(data=[])

    def test_variable_size_list_deserialization_rejects_too_small_scope(self) -> None:
        """Tests variable-size lists require at least one offset word."""
        with pytest.raises(SSZSerializationError, match="scope 3 too small"):
            VariableContainerList2.decode_bytes(b"\x00\x00\x00")

    def test_variable_size_list_deserialization_rejects_invalid_first_offset(self) -> None:
        """Tests variable-size lists reject misaligned offsets."""
        with pytest.raises(SSZSerializationError, match="invalid offset 1"):
            VariableContainerList2.decode_bytes(b"\x01\x00\x00\x00")

    def test_variable_size_list_deserialization_rejects_count_beyond_limit(self) -> None:
        """Tests variable-size lists reject counts beyond their limit."""
        bad_payload = b"\x0c\x00\x00\x00" + (b"\x00" * 8)

        with pytest.raises(SSZValueError, match="exceeds limit of 2, got 3"):
            VariableContainerList2.decode_bytes(bad_payload)
