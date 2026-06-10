"""Tests for the SSZVector and SSZList types."""

from typing import Any, cast

import pytest
from hypothesis import given, strategies as st
from pydantic import BaseModel, ValidationError

from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.ssz import Bytes32, Uint8, Uint16, Uint32
from lean_spec.spec.ssz.boolean import Boolean
from lean_spec.spec.ssz.collections import SSZList, SSZVector
from lean_spec.spec.ssz.container import Container
from lean_spec.spec.ssz.exceptions import SSZSerializationError, SSZTypeError, SSZValueError

ValueOrValidationError = (SSZValueError, ValidationError)
TypeOrValidationError = (SSZTypeError, ValidationError)


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


class FixedContainerList2(SSZList[FixedContainer]):
    """A list with up to 2 FixedContainer values."""

    LIMIT = 2


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


class Uint8Vector2Model(BaseModel):
    """Model for testing Pydantic validation of Uint8Vector2."""

    value: Uint8Vector2


class Uint8List4Model(BaseModel):
    """Model for testing Pydantic validation of Uint8List4."""

    value: Uint8List4


class TestSSZVectorValidator:
    """Tests for the SSZVector field validator and its rejection paths."""

    def test_missing_element_type_and_length_rejected(self) -> None:
        """A subclass without ELEMENT_TYPE or LENGTH cannot validate any input."""

        class MissingBoth(SSZVector):
            pass

        with pytest.raises(TypeOrValidationError) as exception_info:
            MissingBoth(data=cast(Any, [1]))
        assert str(exception_info.value) == "MissingBoth must define ELEMENT_TYPE and LENGTH"

    def test_missing_length_rejected(self) -> None:
        """A subclass with ELEMENT_TYPE but no LENGTH cannot validate."""

        class MissingLengthVector(SSZVector[Uint8]):
            pass

        with pytest.raises(TypeOrValidationError) as exception_info:
            MissingLengthVector(data=cast(Any, [1]))
        assert (
            str(exception_info.value) == "MissingLengthVector must define ELEMENT_TYPE and LENGTH"
        )

    @pytest.mark.parametrize(
        "bad_input, type_name",
        [
            ("ab", "str"),
            (b"ab", "bytes"),
            (bytearray(b"ab"), "bytearray"),
        ],
    )
    def test_byte_like_inputs_rejected(self, bad_input: Any, type_name: str) -> None:
        """Strings, bytes, and bytearrays never iterate as element collections."""
        with pytest.raises(TypeOrValidationError) as exception_info:
            Uint8Vector2(data=bad_input)
        assert (
            str(exception_info.value)
            == f"Uint8Vector2: Expected iterable of Uint8, got {type_name}"
        )

    def test_non_iterable_scalar_rejected(self) -> None:
        """Scalar inputs without an iterator interface raise an iterable error."""
        with pytest.raises(TypeOrValidationError) as exception_info:
            Uint8Vector2(data=cast(Any, 42))
        assert str(exception_info.value) == "Uint8Vector2: Expected iterable, got int"

    def test_generator_input_coerced(self) -> None:
        """A generator is materialized and each value is coerced to ELEMENT_TYPE."""
        instance = Uint8Vector4(data=cast(Any, (number for number in range(1, 5))))

        assert tuple(instance) == (Uint8(1), Uint8(2), Uint8(3), Uint8(4))

    def test_already_typed_elements_pass_through(self) -> None:
        """Inputs already typed as ELEMENT_TYPE skip the coercion constructor."""
        original = [Uint8(1), Uint8(2), Uint8(3), Uint8(4)]
        instance = Uint8Vector4(data=original)

        assert tuple(instance) == tuple(original)

    def test_raw_values_coerced_through_element_type(self) -> None:
        """Raw Python ints are coerced through the declared element type."""
        instance = Uint8Vector4(data=cast(Any, [1, 2, 3, 4]))

        assert tuple(instance) == (Uint8(1), Uint8(2), Uint8(3), Uint8(4))

    def test_element_coercion_failure_includes_chained_cause(self) -> None:
        """A failed element coercion surfaces both the outer and inner error message."""
        with pytest.raises(TypeOrValidationError) as exception_info:
            Uint8Vector4(data=cast(Any, [1, "bad", 3, 4]))
        assert str(exception_info.value) == "Expected Uint8, got str: Expected int, got str"

    def test_too_few_elements_rejected(self) -> None:
        """A vector requires exactly LENGTH elements and rejects shorter inputs."""
        with pytest.raises(ValueOrValidationError) as exception_info:
            Uint8Vector4(data=cast(Any, [1, 2, 3]))
        assert str(exception_info.value) == "Uint8Vector4 requires exactly 4 elements, got 3"

    def test_too_many_elements_rejected(self) -> None:
        """A vector requires exactly LENGTH elements and rejects longer inputs."""
        with pytest.raises(ValueOrValidationError) as exception_info:
            Uint8Vector4(data=cast(Any, [1, 2, 3, 4, 5]))
        assert str(exception_info.value) == "Uint8Vector4 requires exactly 4 elements, got 5"


class TestSSZVectorClassMetadata:
    """Tests for SSZVector class-level metadata and inference."""

    def test_class_getitem_creates_specialized_type(self) -> None:
        """Explicit subclasses keep distinct LENGTH and ELEMENT_TYPE bindings."""
        assert Uint8Vector32 is not Uint8Vector64
        assert Uint8Vector32 is not Uint16Vector32
        assert Uint8Vector32.LENGTH == 32
        assert Uint8Vector32.ELEMENT_TYPE is Uint8
        assert "Uint8Vector32" in repr(Uint8Vector32)

    def test_init_subclass_infers_element_type_from_generic(self) -> None:
        """Generic subclasses copy the bracketed type into ELEMENT_TYPE."""

        class LocalVector(SSZVector[Uint16]):
            LENGTH = 1

        assert LocalVector.ELEMENT_TYPE is Uint16

    def test_init_subclass_preserves_explicit_element_type(self) -> None:
        """An explicit ELEMENT_TYPE in the class body wins over generic inference."""

        class LocalVector(SSZVector[Uint8]):
            ELEMENT_TYPE = Uint16
            LENGTH = 1

        assert LocalVector.ELEMENT_TYPE is Uint16

    def test_instantiate_raw_type_raises_error(self) -> None:
        """The raw SSZVector base cannot be instantiated as a Pydantic model."""
        with pytest.raises(
            TypeError,
            match=r"^BaseModel\.__init__\(\) takes 1 positional argument but 2 were given\Z",
        ):
            SSZVector([])  # type: ignore[misc]

    def test_fixed_size_vector_reports_fixed_size_true(self) -> None:
        """A vector of fixed-size elements is itself fixed-size."""
        assert Uint8Vector4.is_fixed_size() is True

    def test_variable_size_vector_reports_fixed_size_false(self) -> None:
        """A vector of variable-size elements is not fixed-size."""
        assert VariableContainerVector2.is_fixed_size() is False

    def test_fixed_size_vector_byte_length_matches_total(self) -> None:
        """Byte length equals the element width times the element count."""
        assert Uint8Vector4.get_byte_length() == 4
        assert Uint16Vector2.get_byte_length() == 4
        assert FixedContainerVector2.get_byte_length() == 6

    def test_variable_size_vector_has_no_fixed_byte_length(self) -> None:
        """Variable-size vectors raise when asked for a fixed byte length."""
        with pytest.raises(SSZTypeError) as exception_info:
            VariableContainerVector2.get_byte_length()
        assert (
            str(exception_info.value)
            == "VariableContainerVector2: variable-size vector has no fixed byte length"
        )


class TestSSZVectorAccessors:
    """Tests for SSZVector accessor and immutability behavior."""

    def test_instantiation_success(self) -> None:
        """Building with the exact element count yields a sequence of typed values."""
        instance = Uint8Vector4(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4)])

        assert len(instance) == 4
        assert list(instance) == [Uint8(1), Uint8(2), Uint8(3), Uint8(4)]

    def test_integer_index_returns_typed_element(self) -> None:
        """Positive integer indexing returns the corresponding typed element."""
        instance = Uint8Vector4(data=[Uint8(10), Uint8(20), Uint8(30), Uint8(40)])

        assert instance[0] == Uint8(10)
        assert instance[2] == Uint8(30)

    def test_negative_index_returns_typed_element(self) -> None:
        """Negative integer indexing addresses elements from the end of the sequence."""
        instance = Uint8Vector4(data=[Uint8(10), Uint8(20), Uint8(30), Uint8(40)])

        assert instance[-1] == Uint8(40)
        assert instance[-4] == Uint8(10)

    def test_slice_returns_sequence(self) -> None:
        """Slicing returns the underlying tuple slice of typed elements."""
        instance = Uint8Vector4(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4)])

        assert instance[1:3] == (Uint8(2), Uint8(3))

    def test_elements_returns_mutable_copy(self) -> None:
        """The elements property exposes a mutable list copy of the data."""
        instance = Uint8Vector4(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4)])

        copy = instance.elements
        copy.append(Uint8(9))

        assert copy == [Uint8(1), Uint8(2), Uint8(3), Uint8(4), Uint8(9)]
        assert list(instance) == [Uint8(1), Uint8(2), Uint8(3), Uint8(4)]

    def test_vector_is_immutable(self) -> None:
        """Item assignment raises because the underlying model is frozen."""
        instance = Uint8Vector2(data=[Uint8(1), Uint8(2)])

        with pytest.raises(TypeError):
            instance[0] = 3  # type: ignore[index]

    def test_pydantic_dict_input_coerces_to_vector(self) -> None:
        """Pydantic coerces a dict payload into an SSZVector with typed elements."""
        instance = Uint8Vector2Model(value=cast(Any, {"data": [10, 20]}))

        assert instance.value == Uint8Vector2(data=[Uint8(10), Uint8(20)])

    def test_pydantic_dict_input_rejects_wrong_length(self) -> None:
        """A dict payload with the wrong element count surfaces the length error."""
        with pytest.raises(ValueOrValidationError) as exception_info:
            Uint8Vector2Model(value=cast(Any, {"data": [10]}))
        assert str(exception_info.value) == "Uint8Vector2 requires exactly 2 elements, got 1"


class TestSSZListValidator:
    """Tests for the SSZList field validator and its rejection paths."""

    def test_missing_element_type_and_limit_rejected(self) -> None:
        """A subclass without ELEMENT_TYPE or LIMIT cannot validate any input."""

        class MissingBoth(SSZList):
            pass

        with pytest.raises(TypeOrValidationError) as exception_info:
            MissingBoth(data=cast(Any, [1]))
        assert str(exception_info.value) == "MissingBoth must define ELEMENT_TYPE and LIMIT"

    def test_missing_limit_rejected(self) -> None:
        """A subclass with ELEMENT_TYPE but no LIMIT cannot validate."""

        class MissingLimitList(SSZList[Uint8]):
            pass

        with pytest.raises(TypeOrValidationError) as exception_info:
            MissingLimitList(data=cast(Any, [1]))
        assert str(exception_info.value) == "MissingLimitList must define ELEMENT_TYPE and LIMIT"

    def test_raw_base_class_rejected(self) -> None:
        """Instantiating the raw SSZList base surfaces the metadata-missing error."""
        with pytest.raises(SSZTypeError) as exception_info:
            SSZList(data=[])
        assert str(exception_info.value) == "SSZList must define ELEMENT_TYPE and LIMIT"

    @pytest.mark.parametrize(
        "bad_input, type_name",
        [
            ("ab", "str"),
            (b"ab", "bytes"),
            (bytearray(b"ab"), "bytearray"),
        ],
    )
    def test_byte_like_inputs_rejected(self, bad_input: Any, type_name: str) -> None:
        """Strings, bytes, and bytearrays never iterate as element collections."""
        with pytest.raises(TypeOrValidationError) as exception_info:
            Uint8List4(data=bad_input)
        assert (
            str(exception_info.value) == f"Uint8List4: Expected iterable of Uint8, got {type_name}"
        )

    def test_non_iterable_scalar_rejected(self) -> None:
        """Scalar inputs without an iterator interface raise an iterable error."""
        with pytest.raises(TypeOrValidationError) as exception_info:
            Uint8List4(data=cast(Any, 5))
        assert str(exception_info.value) == "Uint8List4: Expected iterable, got int"

    def test_generator_input_coerced(self) -> None:
        """A generator is materialized and each value is coerced to ELEMENT_TYPE."""
        instance = Uint8List4(data=cast(Any, (number for number in range(3))))

        assert list(instance) == [Uint8(0), Uint8(1), Uint8(2)]

    def test_already_typed_elements_pass_through(self) -> None:
        """Inputs already typed as ELEMENT_TYPE skip the coercion constructor."""
        instance = Uint8List4(data=[Uint8(1), Uint8(2)])

        assert list(instance) == [Uint8(1), Uint8(2)]

    def test_raw_values_coerced_through_element_type(self) -> None:
        """Raw Python ints are coerced through the declared element type."""
        instance = Uint8List4(data=cast(Any, [1, 2, 3]))

        assert list(instance) == [Uint8(1), Uint8(2), Uint8(3)]

    def test_element_coercion_failure_includes_chained_cause(self) -> None:
        """A failed element coercion surfaces both the outer and inner error message."""
        with pytest.raises(TypeOrValidationError) as exception_info:
            Uint8List4(data=cast(Any, [1, "bad"]))
        assert str(exception_info.value) == "Expected Uint8, got str: Expected int, got str"

    def test_empty_list_allowed(self) -> None:
        """A list with zero elements is always valid, regardless of LIMIT."""
        instance = Uint8List4(data=[])

        assert list(instance) == []
        assert len(instance) == 0

    def test_construction_at_limit_allowed(self) -> None:
        """A list with exactly LIMIT elements is valid."""
        instance = Uint8List4(data=cast(Any, [1, 2, 3, 4]))

        assert list(instance) == [Uint8(1), Uint8(2), Uint8(3), Uint8(4)]

    def test_over_limit_rejected(self) -> None:
        """A list with more than LIMIT elements raises the exceeds-limit error."""
        with pytest.raises(ValueOrValidationError) as exception_info:
            Uint8List4(data=cast(Any, [1, 2, 3, 4, 5]))
        assert str(exception_info.value) == "Uint8List4 exceeds limit of 4, got 5"

    def test_over_limit_rejected_for_boolean_list(self) -> None:
        """The same exceeds-limit error fires for a list of booleans."""
        with pytest.raises(ValueOrValidationError) as exception_info:
            BooleanList4(data=[Boolean(True)] * 5)
        assert str(exception_info.value) == "BooleanList4 exceeds limit of 4, got 5"


class TestSSZListClassMetadata:
    """Tests for SSZList class-level metadata and inference."""

    def test_class_getitem_creates_specialized_type(self) -> None:
        """Explicit subclasses keep distinct LIMIT and ELEMENT_TYPE bindings."""
        assert Uint8List32 is not Uint8List64
        assert Uint8List32 is not Uint16List32
        assert Uint8List32.LIMIT == 32
        assert Uint8List32.ELEMENT_TYPE is Uint8
        assert "Uint8List32" in repr(Uint8List32)

    def test_init_subclass_infers_element_type_from_generic(self) -> None:
        """Generic subclasses copy the bracketed type into ELEMENT_TYPE."""

        class LocalList(SSZList[Uint16]):
            LIMIT = 2

        assert LocalList.ELEMENT_TYPE is Uint16

    def test_list_is_never_fixed_size(self) -> None:
        """A list never collapses to a fixed-size encoding."""
        assert Uint8List4.is_fixed_size() is False
        assert VariableContainerList2.is_fixed_size() is False

    def test_get_byte_length_always_raises(self) -> None:
        """A list type has no fixed byte length even for fixed-size elements."""
        with pytest.raises(SSZTypeError) as exception_info:
            Uint8List4.get_byte_length()
        assert (
            str(exception_info.value) == "Uint8List4: variable-size list has no fixed byte length"
        )

    def test_get_byte_length_raises_for_variable_element_list(self) -> None:
        """The same error fires for lists whose elements are variable-size."""
        with pytest.raises(SSZTypeError) as exception_info:
            VariableContainerList2.get_byte_length()
        assert (
            str(exception_info.value)
            == "VariableContainerList2: variable-size list has no fixed byte length"
        )


class TestSSZListAccessors:
    """Tests for SSZList accessor and concatenation behavior."""

    def test_integer_index_returns_typed_element(self) -> None:
        """Positive integer indexing returns the corresponding typed element."""
        instance = Uint8List4(data=[Uint8(10), Uint8(20), Uint8(30)])

        assert instance[0] == Uint8(10)
        assert instance[2] == Uint8(30)

    def test_negative_index_returns_typed_element(self) -> None:
        """Negative integer indexing addresses elements from the end of the sequence."""
        instance = Uint8List4(data=[Uint8(10), Uint8(20), Uint8(30)])

        assert instance[-1] == Uint8(30)
        assert instance[-3] == Uint8(10)

    def test_slice_returns_sequence(self) -> None:
        """Slicing returns the underlying tuple slice of typed elements."""
        instance = Uint8List4(data=[Uint8(1), Uint8(2), Uint8(3)])

        assert instance[1:3] == (Uint8(2), Uint8(3))

    def test_elements_returns_mutable_copy(self) -> None:
        """The elements property exposes a mutable list copy of the data."""
        instance = Uint8List4(data=[Uint8(1), Uint8(2), Uint8(3)])

        copy = instance.elements
        copy.append(Uint8(9))

        assert copy == [Uint8(1), Uint8(2), Uint8(3), Uint8(9)]
        assert list(instance) == [Uint8(1), Uint8(2), Uint8(3)]

    def test_pydantic_dict_input_coerces_to_list(self) -> None:
        """Pydantic coerces a list payload into an SSZList with typed elements."""
        instance = Uint8List4Model(value=Uint8List4(data=[Uint8(10), Uint8(20)]))

        assert instance.value == Uint8List4(data=[Uint8(10), Uint8(20)])

    def test_add_with_sszlist(self) -> None:
        """Concatenating two SSZLists yields a fresh list of the same type."""
        concatenated = Uint8List10(data=[Uint8(1), Uint8(2)]) + Uint8List10(
            data=[Uint8(3), Uint8(4)]
        )

        assert concatenated == Uint8List10(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4)])
        assert isinstance(concatenated, Uint8List10)

    def test_add_with_plain_list(self) -> None:
        """Concatenating with a plain list coerces the right-hand values."""
        concatenated = Uint8List10(data=[Uint8(1), Uint8(2), Uint8(3)]) + [4, 5]

        assert concatenated == Uint8List10(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4), Uint8(5)])

    def test_add_with_tuple(self) -> None:
        """Concatenating with a tuple coerces the right-hand values."""
        concatenated = Uint8List10(data=[Uint8(1), Uint8(2)]) + (3, 4)

        assert concatenated == Uint8List10(data=[Uint8(1), Uint8(2), Uint8(3), Uint8(4)])

    def test_add_empty_to_empty(self) -> None:
        """Concatenating two empty lists yields an empty list of the same type."""
        concatenated = Uint8List10(data=[]) + Uint8List10(data=[])

        assert concatenated == Uint8List10(data=[])

    def test_add_empty_to_non_empty(self) -> None:
        """Concatenating an empty list to a populated one preserves the populated list."""
        populated = Uint8List10(data=[Uint8(1), Uint8(2)])
        concatenated = Uint8List10(data=[]) + populated

        assert concatenated == populated

    def test_add_non_empty_to_empty(self) -> None:
        """Concatenating a populated list to an empty one preserves the populated list."""
        populated = Uint8List10(data=[Uint8(1), Uint8(2)])
        concatenated = populated + Uint8List10(data=[])

        assert concatenated == populated

    def test_add_unsupported_type_returns_not_implemented(self) -> None:
        """Unsupported operands return NotImplemented from the add hook."""
        instance = Uint8List10(data=[Uint8(1), Uint8(2)])

        assert instance.__add__(object()) is NotImplemented

    def test_add_exceeding_limit_raises_error(self) -> None:
        """Concatenation that overflows LIMIT raises the exceeds-limit error."""
        base = Uint8List4(data=[Uint8(1), Uint8(2), Uint8(3)])
        with pytest.raises(ValueOrValidationError) as exception_info:
            base + [4, 5]
        assert str(exception_info.value) == "Uint8List4 exceeds limit of 4, got 5"


class TestSSZVectorSerialization:
    """Tests SSZ serialization and deserialization for SSZVector."""

    @pytest.mark.parametrize(
        "vector_type, elements, expected_hex",
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
                tuple(
                    1 if i == 0 else 2 if i == 32 else 3 if i == 64 else 0xFF if i == 95 else 0
                    for i in range(96)
                ),
                "0100000000000000000000000000000000000000000000000000000000000000"
                "0200000000000000000000000000000000000000000000000000000000000000"
                "03000000000000000000000000000000000000000000000000000000000000ff",
            ),
            (
                FixedContainerVector2,
                (
                    FixedContainer(a=Uint8(1), b=Uint16(2)),
                    FixedContainer(a=Uint8(3), b=Uint16(4)),
                ),
                "010200030400",
            ),
            (
                FpVector8,
                (10, 20, 30, 40, 50, 60, 70, 80),
                "0a000000140000001e00000028000000320000003c0000004600000050000000",
            ),
        ],
    )
    def test_fixed_size_element_vector_roundtrip(
        self,
        vector_type: type[SSZVector],
        elements: tuple[Any, ...],
        expected_hex: str,
    ) -> None:
        """Fixed-size vectors encode to a known hex layout and round-trip back."""
        instance = vector_type(data=elements)
        encoded = instance.encode_bytes()

        assert encoded.hex() == expected_hex
        assert vector_type.decode_bytes(encoded) == instance

    def test_variable_size_element_vector_roundtrip(self) -> None:
        """Variable-size vectors emit the offset table followed by buffered bodies."""
        val1 = VariableContainer(a=Uint8(1), b=Uint16List4(data=[Uint16(10), Uint16(20)]))
        val2 = VariableContainer(a=Uint8(2), b=Uint16List4(data=[Uint16(30)]))
        instance = VariableContainerVector2(data=[val1, val2])

        expected_hex = "080000001100000001050000000a00140002050000001e00"
        encoded = instance.encode_bytes()

        assert encoded.hex() == expected_hex
        assert VariableContainerVector2.decode_bytes(encoded) == instance

    def test_fixed_size_vector_rejects_scope_too_small(self) -> None:
        """A fixed-size vector rejects payloads shorter than its byte budget."""
        with pytest.raises(SSZSerializationError) as exception_info:
            Uint8Vector4.decode_bytes(b"\x00\x01\x02")
        assert str(exception_info.value) == "Uint8Vector4: expected 4 bytes, got 3"

    def test_fixed_size_vector_rejects_scope_too_large(self) -> None:
        """A fixed-size vector rejects payloads larger than its byte budget."""
        with pytest.raises(SSZSerializationError) as exception_info:
            Uint8Vector4.decode_bytes(b"\x00\x01\x02\x03\x04")
        assert str(exception_info.value) == "Uint8Vector4: expected 4 bytes, got 5"

    def test_variable_size_vector_rejects_scope_below_offset_table(self) -> None:
        """A scope smaller than the offset table cannot describe any layout."""
        with pytest.raises(SSZSerializationError) as exception_info:
            VariableContainerVector2.decode_bytes(b"\x00\x00\x00")
        assert (
            str(exception_info.value)
            == "VariableContainerVector2: scope 3 too small, expected at least 8"
        )

    def test_variable_size_vector_rejects_invalid_first_offset(self) -> None:
        """The first offset must point past the offset table."""
        with pytest.raises(SSZSerializationError) as exception_info:
            VariableContainerVector2.decode_bytes(b"\x04\x00\x00\x00\x08\x00\x00\x00")
        assert str(exception_info.value) == "VariableContainerVector2: invalid offset 4, expected 8"

    def test_variable_size_vector_rejects_non_monotonic_offsets(self) -> None:
        """A later offset smaller than an earlier one means a body would have negative width."""
        # Layout:
        #
        #     offsets[0] = 8   (table-end, valid first offset)
        #     offsets[1] = 6   (decreasing, triggers the monotonic check)
        encoded_bytes = b"\x08\x00\x00\x00\x06\x00\x00\x00"
        with pytest.raises(SSZSerializationError) as exception_info:
            VariableContainerVector2.decode_bytes(encoded_bytes)
        assert (
            str(exception_info.value)
            == "VariableContainerVector2: offsets not monotonically increasing: 8 -> 6"
        )

    def test_variable_size_vector_rejects_final_offset_overflow(self) -> None:
        """A final offset that exceeds the scope triggers the monotonic check first."""
        # Layout:
        #
        #     offsets[0] = 8       (table-end, valid first offset)
        #     offsets[1] = 100     (past scope of 20, but also greater than next, scope=20)
        #
        # Pairwise iteration appends scope as the final boundary, so the 100 -> 20
        # transition trips the monotonic check before the final-offset-exceeds-scope check.
        encoded_bytes = b"\x08\x00\x00\x00\x64\x00\x00\x00" + b"\x00" * 12
        with pytest.raises(SSZSerializationError) as exception_info:
            VariableContainerVector2.decode_bytes(encoded_bytes)
        assert (
            str(exception_info.value)
            == "VariableContainerVector2: offsets not monotonically increasing: 100 -> 20"
        )


class TestSSZListSerialization:
    """Tests SSZ serialization and deserialization for SSZList."""

    @pytest.mark.parametrize(
        "list_type, elements, expected_hex",
        [
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
    def test_fixed_size_element_list_roundtrip(
        self,
        list_type: type[SSZList],
        elements: tuple[Any, ...],
        expected_hex: str,
    ) -> None:
        """Fixed-size lists pack bodies back-to-back without separators."""
        instance = list_type(data=elements)
        encoded = instance.encode_bytes()

        assert encoded.hex() == expected_hex
        assert list_type.decode_bytes(encoded) == instance

    def test_variable_size_element_list_roundtrip(self) -> None:
        """Variable-size lists emit a runtime-sized offset table before the bodies."""
        val1 = VariableContainer(a=Uint8(1), b=Uint16List4(data=[Uint16(10)]))
        val2 = VariableContainer(a=Uint8(2), b=Uint16List4(data=[Uint16(30), Uint16(40)]))
        instance = VariableContainerList2(data=[val1, val2])

        expected_hex = "080000000f00000001050000000a0002050000001e002800"
        encoded = instance.encode_bytes()

        assert encoded.hex() == expected_hex
        assert VariableContainerList2.decode_bytes(encoded) == instance

    def test_empty_scope_decodes_to_empty_list(self) -> None:
        """An empty payload always decodes to an empty list."""
        assert VariableContainerList2.decode_bytes(b"") == VariableContainerList2(data=[])

    def test_fixed_size_list_rejects_scope_not_divisible_by_element_size(self) -> None:
        """A fixed-size list rejects payloads whose length is not a multiple of the stride."""
        with pytest.raises(SSZSerializationError) as exception_info:
            Uint16List4.decode_bytes(b"\x01")
        assert str(exception_info.value) == "Uint16List4: scope 1 not divisible by element size 2"

    def test_fixed_size_list_rejects_count_beyond_limit(self) -> None:
        """A fixed-size list rejects payloads that decode to more than LIMIT elements."""
        with pytest.raises(SSZValueError) as exception_info:
            Uint8List4.decode_bytes(b"\x00\x01\x02\x03\x04")
        assert str(exception_info.value) == "Uint8List4 exceeds limit of 4, got 5"

    def test_variable_size_list_rejects_scope_below_offset_word(self) -> None:
        """A variable-size list requires at least one offset word in the payload."""
        with pytest.raises(SSZSerializationError) as exception_info:
            VariableContainerList2.decode_bytes(b"\x00\x00\x00")
        assert (
            str(exception_info.value)
            == "VariableContainerList2: scope 3 too small for variable-size list"
        )

    def test_variable_size_list_rejects_first_offset_past_scope(self) -> None:
        """A first offset larger than the available scope is invalid."""
        with pytest.raises(SSZSerializationError) as exception_info:
            VariableContainerList2.decode_bytes(b"\x64\x00\x00\x00")
        assert str(exception_info.value) == "VariableContainerList2: invalid offset 100"

    def test_variable_size_list_rejects_misaligned_first_offset(self) -> None:
        """A first offset that is not a multiple of the offset width is invalid."""
        with pytest.raises(SSZSerializationError) as exception_info:
            VariableContainerList2.decode_bytes(b"\x05\x00\x00\x00\x00\x00\x00\x00")
        assert str(exception_info.value) == "VariableContainerList2: invalid offset 5"

    def test_variable_size_list_rejects_count_beyond_limit(self) -> None:
        """A first offset that implies more than LIMIT elements is rejected."""
        # Layout:
        #
        #     first_offset = 12   (count = 12 / 4 = 3, above LIMIT=2)
        encoded_bytes = b"\x0c\x00\x00\x00" + b"\x00" * 8
        with pytest.raises(SSZValueError) as exception_info:
            VariableContainerList2.decode_bytes(encoded_bytes)
        assert str(exception_info.value) == "VariableContainerList2 exceeds limit of 2, got 3"

    def test_variable_size_list_rejects_non_monotonic_offsets(self) -> None:
        """A later offset smaller than an earlier one means a body would have negative width."""
        # Layout:
        #
        #     first_offset = 8     (count = 2, table-end)
        #     offsets[1]   = 6     (decreasing, triggers the monotonic check)
        encoded_bytes = b"\x08\x00\x00\x00\x06\x00\x00\x00" + b"\x00" * 12
        with pytest.raises(SSZSerializationError) as exception_info:
            VariableContainerList2.decode_bytes(encoded_bytes)
        assert (
            str(exception_info.value)
            == "VariableContainerList2: offsets not monotonically increasing: 8 -> 6"
        )

    def test_variable_size_list_rejects_final_offset_overflow(self) -> None:
        """An interior offset past the payload's end triggers the monotonic check."""
        encoded_bytes = b"\x08\x00\x00\x00\x64\x00\x00\x00" + b"\x00" * 12
        with pytest.raises(SSZSerializationError) as exception_info:
            VariableContainerList2.decode_bytes(encoded_bytes)
        assert (
            str(exception_info.value)
            == "VariableContainerList2: offsets not monotonically increasing: 100 -> 20"
        )

    def test_variable_size_list_single_element_decodes(self) -> None:
        """A single-element list reads no further offsets after the first."""
        element = VariableContainer(a=Uint8(1), b=Uint16List4(data=[Uint16(10)]))
        encoded = VariableContainerList2(data=[element]).encode_bytes()

        assert VariableContainerList2.decode_bytes(encoded) == VariableContainerList2(
            data=[element]
        )


class TestJsonSerialization:
    """Tests for the JSON field serializer on SSZ sequences."""

    def test_byte_array_elements_render_as_hex_strings(self) -> None:
        """Byte-array leaves render as 0x-prefixed hex strings in JSON output."""
        instance = Bytes32List32(data=[Bytes32.zero()])

        assert instance.model_dump(mode="json") == {"data": ["0x" + ("00" * 32)]}

    def test_integer_elements_render_as_plain_ints(self) -> None:
        """Field-element leaves flatten to plain Python ints in JSON output."""
        instance = FpVector8(data=[Fp(1), Fp(2), Fp(3), Fp(4), Fp(5), Fp(6), Fp(7), Fp(8)])

        assert instance.model_dump(mode="json") == {"data": [1, 2, 3, 4, 5, 6, 7, 8]}

    def test_boolean_elements_render_as_true_false(self) -> None:
        """Booleans are excluded from the int branch and stay as true/false."""
        instance = BooleanList4(data=[Boolean(True), Boolean(False), Boolean(True)])

        assert instance.model_dump(mode="json") == {"data": [True, False, True]}

    def test_container_elements_pass_through_to_pydantic(self) -> None:
        """Container elements fall through the else branch and recurse via Pydantic."""
        instance = FixedContainerList2(
            data=[
                FixedContainer(a=Uint8(1), b=Uint16(2)),
                FixedContainer(a=Uint8(3), b=Uint16(4)),
            ]
        )

        assert instance.model_dump(mode="json") == {"data": [{"a": 1, "b": 2}, {"a": 3, "b": 4}]}


@given(values=st.lists(st.integers(min_value=0, max_value=2**16 - 1), max_size=4))
def test_list_round_trip_random_values(values: list[int]) -> None:
    """Any element sequence up to the limit, including empty, round-trips unchanged."""
    instance = Uint16List4(data=[Uint16(value) for value in values])
    assert Uint16List4.decode_bytes(instance.encode_bytes()) == instance


@given(values=st.lists(st.integers(min_value=0, max_value=255), min_size=4, max_size=4))
def test_vector_round_trip_random_values(values: list[int]) -> None:
    """Any fixed-length element sequence round-trips unchanged."""
    instance = Uint8Vector4(data=[Uint8(value) for value in values])
    assert Uint8Vector4.decode_bytes(instance.encode_bytes()) == instance
