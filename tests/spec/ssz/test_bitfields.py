"""Tests for the Bitvector and Bitlist types."""

import io
from typing import Any

import pytest
from hypothesis import given, strategies as st
from pydantic import BaseModel, ValidationError

from lean_spec.spec.ssz.bitfields import BaseBitlist, BaseBitvector
from lean_spec.spec.ssz.boolean import Boolean
from lean_spec.spec.ssz.exceptions import SSZSerializationError, SSZTypeError, SSZValueError

# Errors that may be raised either directly or wrapped by Pydantic at construction time.
ValueOrValidationError = (SSZValueError, ValidationError)


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
    """Tests for the fixed-length Bitvector type."""

    def test_class_creates_specialized_type(self) -> None:
        """Concrete Bitvector classes carry the declared length."""

        class Bitvector8(BaseBitvector):
            LENGTH = 8

        class Bitvector16(BaseBitvector):
            LENGTH = 16

        assert Bitvector8.LENGTH == 8
        assert Bitvector16.LENGTH == 16
        assert "Bitvector8" in repr(Bitvector8)

    def test_instantiate_raw_type_raises_error(self) -> None:
        """Direct instantiation of the abstract base raises SSZTypeError."""
        with pytest.raises(SSZTypeError) as exception_info:
            BaseBitvector(data=[])
        assert str(exception_info.value) == "BaseBitvector must define LENGTH"

    def test_instantiation_success(self) -> None:
        """Instantiation succeeds with exactly LENGTH boolean items."""
        instance = Bitvector4(data=[Boolean(True), Boolean(False), Boolean(1), Boolean(0)])
        assert len(instance) == 4
        assert instance == Bitvector4(
            data=[Boolean(True), Boolean(False), Boolean(True), Boolean(False)]
        )

    def test_instantiation_from_generator(self) -> None:
        """Fixed-length type materializes a generator into a tuple before validation."""
        bit_generator = (Boolean(bit) for bit in [True, False, True, False])
        instance = Bitvector4(data=bit_generator)  # type: ignore[arg-type]
        assert len(instance) == 4

    @pytest.mark.parametrize(
        "bits, expected_element_count",
        [
            ([Boolean(True), Boolean(False), Boolean(True)], 3),
            (
                [Boolean(True), Boolean(False), Boolean(True), Boolean(False), Boolean(True)],
                5,
            ),
        ],
    )
    def test_instantiation_with_wrong_length_raises_error(
        self, bits: list[Boolean], expected_element_count: int
    ) -> None:
        """Wrong-length input raises with the exact element count in the message."""
        with pytest.raises(ValueOrValidationError) as exception_info:
            Bitvector4(data=bits)
        assert (
            str(exception_info.value)
            == f"Bitvector4 requires exactly 4 elements, got {expected_element_count}"
        )

    def test_pydantic_validation_accepts_valid_list(self) -> None:
        """Pydantic validation accepts a valid list of booleans."""
        bits = [Boolean(True), Boolean(False), Boolean(True), Boolean(False)]
        instance = Bitvector4Model(value={"data": bits})  # type: ignore[arg-type]
        assert isinstance(instance.value, Bitvector4)
        assert instance.value == Bitvector4(data=bits)

    @pytest.mark.parametrize(
        "invalid_value",
        [
            {"data": [Boolean(True), Boolean(False), Boolean(True)]},
            {"data": [Boolean(bit) for bit in [True, False, True, False, True]]},
        ],
    )
    def test_pydantic_validation_rejects_wrong_length(self, invalid_value: Any) -> None:
        """Pydantic validation rejects lists of the wrong length."""
        with pytest.raises(ValueOrValidationError):
            Bitvector4Model(value=invalid_value)

    def test_bitvector_is_immutable(self) -> None:
        """Item assignment on a Bitvector raises TypeError — Pydantic models are immutable."""

        class Bitvector2(BaseBitvector):
            LENGTH = 2

        vec = Bitvector2(data=[Boolean(True), Boolean(False)])
        with pytest.raises(TypeError):
            vec[0] = False  # type: ignore[index]


class TestBitlist:
    """Tests for the variable-length Bitlist type."""

    def test_class_creates_specialized_type(self) -> None:
        """Concrete Bitlist classes carry the declared limit."""

        class Bitlist8(BaseBitlist):
            LIMIT = 8

        class Bitlist16(BaseBitlist):
            LIMIT = 16

        assert Bitlist8.LIMIT == 8
        assert Bitlist16.LIMIT == 16
        assert "Bitlist8" in repr(Bitlist8)

    def test_instantiate_raw_type_raises_error(self) -> None:
        """Direct instantiation of the abstract base raises SSZTypeError."""
        with pytest.raises(SSZTypeError) as exception_info:
            BaseBitlist(data=[])
        assert str(exception_info.value) == "BaseBitlist must define LIMIT"

    def test_instantiation_success(self) -> None:
        """Instantiation succeeds with any number of items up to LIMIT."""
        instance = Bitlist8(data=[Boolean(True), Boolean(False), Boolean(1), Boolean(0)])
        assert len(instance) == 4
        expected_bitlist = Bitlist8(
            data=[Boolean(True), Boolean(False), Boolean(True), Boolean(False)]
        )
        assert instance == expected_bitlist

    def test_instantiation_from_generator(self) -> None:
        """Variable-length type materializes a generator into a list before validation."""
        bit_generator = (Boolean(bit) for bit in [True, False, True])
        instance = Bitlist8(data=bit_generator)  # type: ignore[arg-type]
        assert len(instance) == 3

    @pytest.mark.parametrize(
        "non_iterable, type_name",
        [
            (42, "int"),
            (None, "NoneType"),
            (1.5, "float"),
        ],
    )
    def test_instantiation_from_non_iterable_raises(
        self, non_iterable: Any, type_name: str
    ) -> None:
        """Non-iterable input raises SSZTypeError naming the offending type."""
        with pytest.raises((SSZTypeError, ValidationError)) as exception_info:
            Bitlist8(data=non_iterable)
        assert str(exception_info.value) == f"Expected iterable, got {type_name}"

    @pytest.mark.parametrize("rejected", ["0101", b"\x00\x01"])
    def test_instantiation_from_str_or_bytes_raises(self, rejected: Any) -> None:
        """str and bytes are iterable but explicitly rejected — their elements are not booleans."""
        type_name = type(rejected).__name__
        with pytest.raises((SSZTypeError, ValidationError)) as exception_info:
            Bitlist8(data=rejected)
        assert str(exception_info.value) == f"Expected iterable, got {type_name}"

    def test_instantiation_over_limit_raises_error(self) -> None:
        """Input exceeding LIMIT raises with the exact size in the message."""

        class Bitlist4(BaseBitlist):
            LIMIT = 4

        with pytest.raises(ValueOrValidationError) as exception_info:
            Bitlist4(data=[Boolean(bit) for bit in [True, False, True, False, True]])
        assert str(exception_info.value) == "Bitlist4 exceeds limit of 4, got 5"

    def test_pydantic_validation_accepts_valid_list(self) -> None:
        """Pydantic validation accepts a valid list of booleans."""
        bits = [Boolean(True), Boolean(False), Boolean(True), Boolean(False)]
        instance = Bitlist8Model(value={"data": bits})  # type: ignore[arg-type]
        assert isinstance(instance.value, Bitlist8)
        assert len(instance.value) == 4

    def test_pydantic_validation_rejects_oversized_list(self) -> None:
        """Pydantic validation rejects lists exceeding the limit."""
        invalid_value = {"data": [Boolean(True)] * 9}
        with pytest.raises(ValueOrValidationError):
            Bitlist8Model(value=invalid_value)  # type: ignore[arg-type]

    def test_get_item_int(self) -> None:
        """Indexing by int returns the Boolean at that position."""
        bitlist = Bitlist8(data=[Boolean(True), Boolean(False), Boolean(True)])
        assert bitlist[0] == Boolean(True)
        assert bitlist[1] == Boolean(False)
        assert bitlist[2] == Boolean(True)

    def test_get_item_slice(self) -> None:
        """Indexing by slice returns a list of Booleans."""
        bitlist = Bitlist8(data=[Boolean(True), Boolean(False), Boolean(True), Boolean(False)])
        sliced_bits = bitlist[1:3]
        assert sliced_bits == [Boolean(False), Boolean(True)]
        assert isinstance(sliced_bits, list)

    def test_add_with_list(self) -> None:
        """Concatenating a Bitlist with a list returns a new instance."""
        bitlist = Bitlist8(data=[Boolean(True), Boolean(False), Boolean(True)])
        concatenated = bitlist + [Boolean(False), Boolean(True)]
        assert len(concatenated) == 5
        assert list(concatenated.data) == [
            Boolean(True),
            Boolean(False),
            Boolean(True),
            Boolean(False),
            Boolean(True),
        ]
        assert isinstance(concatenated, Bitlist8)

    def test_add_with_bitlist(self) -> None:
        """Concatenating two Bitlists of the same type returns a new instance."""
        bitlist1 = Bitlist8(data=[Boolean(True), Boolean(False)])
        bitlist2 = Bitlist8(data=[Boolean(True), Boolean(True)])
        concatenated = bitlist1 + bitlist2
        assert len(concatenated) == 4
        assert list(concatenated.data) == [
            Boolean(True),
            Boolean(False),
            Boolean(True),
            Boolean(True),
        ]
        assert isinstance(concatenated, Bitlist8)

    def test_add_with_unsupported_type_raises(self) -> None:
        """Adding an unsupported type returns NotImplemented and Python raises TypeError."""
        bitlist = Bitlist8(data=[Boolean(True)])
        with pytest.raises(TypeError):
            _ = bitlist + 42

    def test_add_exceeding_limit_raises_error(self) -> None:
        """Concatenation beyond LIMIT raises with the exact size in the message."""

        class Bitlist4(BaseBitlist):
            LIMIT = 4

        bitlist = Bitlist4(data=[Boolean(True), Boolean(False), Boolean(True)])
        with pytest.raises(ValueOrValidationError) as exception_info:
            _ = bitlist + [Boolean(False), Boolean(True)]
        assert str(exception_info.value) == "Bitlist4 exceeds limit of 4, got 5"


class TestBitfieldSSZ:
    """SSZ interface methods and end-to-end serialization round-trips."""

    def test_bitvector_is_fixed_size(self) -> None:
        """Bitvector reports fixed-size and computes byte length via ceil(LENGTH / 8)."""

        class Bitvector10(BaseBitvector):
            LENGTH = 10

        assert Bitvector10.is_fixed_size() is True
        assert Bitvector10.get_byte_length() == 2

    def test_bitlist_is_variable_size(self) -> None:
        """Bitlist reports variable-size and get_byte_length raises."""

        class Bitlist10(BaseBitlist):
            LIMIT = 10

        assert Bitlist10.is_fixed_size() is False
        with pytest.raises(SSZTypeError) as exception_info:
            Bitlist10.get_byte_length()
        assert (
            str(exception_info.value) == "Bitlist10: variable-size bitlist has no fixed byte length"
        )

    @pytest.mark.parametrize(
        "length, bits, expected_hex",
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
    def test_bitvector_round_trip(
        self, length: int, bits: tuple[int, ...], expected_hex: str
    ) -> None:
        """Bitvector round-trips through encode_bytes, decode_bytes, and stream serialization."""

        class TestBitvector(BaseBitvector):
            LENGTH = length

        boolean_bits = tuple(Boolean(bit) for bit in bits)
        instance = TestBitvector(data=boolean_bits)

        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex

        decoded = TestBitvector.decode_bytes(encoded)
        assert decoded == instance

        stream = io.BytesIO()
        written = instance.serialize(stream)
        assert written == TestBitvector.get_byte_length()
        stream.seek(0)
        decoded2 = TestBitvector.deserialize(stream, scope=written)
        assert decoded2 == instance

    @pytest.mark.parametrize(
        "limit, bits, expected_hex",
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
    def test_bitlist_round_trip(self, limit: int, bits: tuple[int, ...], expected_hex: str) -> None:
        """Bitlist round-trips through encode_bytes, decode_bytes, and stream serialization."""

        class TestBitlist(BaseBitlist):
            LIMIT = limit

        boolean_bits = tuple(Boolean(bit) for bit in bits)
        instance = TestBitlist(data=boolean_bits)

        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex

        decoded = TestBitlist.decode_bytes(encoded)
        assert decoded == instance

        stream = io.BytesIO()
        written = instance.serialize(stream)
        assert written == len(encoded)
        stream.seek(0)
        decoded2 = TestBitlist.deserialize(stream, scope=written)
        assert decoded2 == instance

    def test_bitvector_decode_invalid_length(self) -> None:
        """Bitvector.decode_bytes rejects inputs whose byte count is wrong."""

        class Bitvector8(BaseBitvector):
            LENGTH = 8

        with pytest.raises(SSZValueError) as exception_info:
            Bitvector8.decode_bytes(b"\x01\x02")
        assert str(exception_info.value) == "Bitvector8: expected 1 bytes, got 2"

    def test_bitvector_deserialize_invalid_scope(self) -> None:
        """Bitvector.deserialize rejects a scope mismatching the type's byte length."""

        class Bitvector8(BaseBitvector):
            LENGTH = 8

        stream = io.BytesIO(b"\xff")
        with pytest.raises(SSZSerializationError) as exception_info:
            Bitvector8.deserialize(stream, scope=2)
        assert str(exception_info.value) == "Bitvector8: expected 1 bytes, got 2"

    def test_bitvector_deserialize_premature_end(self) -> None:
        """Bitvector.deserialize rejects a stream that ends before the declared scope."""

        class Bitvector16(BaseBitvector):
            LENGTH = 16

        stream = io.BytesIO(b"\xff")
        with pytest.raises(SSZSerializationError) as exception_info:
            Bitvector16.deserialize(stream, scope=2)
        assert str(exception_info.value) == "Bitvector16: expected 2 bytes, got 1"

    def test_bitlist_decode_empty_bytes(self) -> None:
        """Bitlist.decode_bytes rejects an empty byte sequence."""

        class Bitlist8(BaseBitlist):
            LIMIT = 8

        with pytest.raises(SSZSerializationError) as exception_info:
            Bitlist8.decode_bytes(b"")
        assert str(exception_info.value) == "Bitlist8: cannot decode empty bytes"

    def test_bitlist_decode_all_zero_bytes(self) -> None:
        """Bitlist.decode_bytes rejects non-empty input with no 1 bits — no delimiter to locate."""

        class Bitlist8(BaseBitlist):
            LIMIT = 8

        with pytest.raises(SSZSerializationError) as exception_info:
            Bitlist8.decode_bytes(b"\x00")
        assert str(exception_info.value) == "Bitlist8: no delimiter bit found"

    def test_bitlist_decode_exceeds_limit(self) -> None:
        """Bitlist.decode_bytes rejects encodings whose recovered bit count exceeds LIMIT."""

        class Bitlist8(BaseBitlist):
            LIMIT = 8

        # Bytes [0xFF, 0xFF, 0x01] mean 16 data bits + delimiter at bit 16 — > LIMIT=8.
        with pytest.raises(SSZValueError) as exception_info:
            Bitlist8.decode_bytes(b"\xff\xff\x01")
        assert str(exception_info.value) == "Bitlist8 exceeds limit of 8, got 16"

    def test_bitlist_deserialize_premature_end(self) -> None:
        """Bitlist.deserialize rejects a stream that ends before the declared scope."""

        class Bitlist16(BaseBitlist):
            LIMIT = 16

        stream = io.BytesIO(b"\xff")
        with pytest.raises(SSZSerializationError) as exception_info:
            Bitlist16.deserialize(stream, scope=2)
        assert str(exception_info.value) == "Bitlist16: expected 2 bytes, got 1"


@given(bits=st.lists(st.booleans(), max_size=8))
def test_bitlist_round_trip_random_bits(bits: list[bool]) -> None:
    """Any bit pattern up to the limit, including empty, round-trips unchanged."""
    instance = Bitlist8(data=tuple(Boolean(bit) for bit in bits))
    assert Bitlist8.decode_bytes(instance.encode_bytes()) == instance


@given(bits=st.lists(st.booleans(), min_size=4, max_size=4))
def test_bitvector_round_trip_random_bits(bits: list[bool]) -> None:
    """Any fixed-length bit pattern round-trips unchanged."""
    instance = Bitvector4(data=tuple(Boolean(bit) for bit in bits))
    assert Bitvector4.decode_bytes(instance.encode_bytes()) == instance
