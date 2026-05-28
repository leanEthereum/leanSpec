"""Tests for the BaseBytes and BaseByteList types."""

import hashlib
import io
import json
import re
from typing import Any

import pytest
from pydantic import BaseModel

from lean_spec.spec.ssz.byte_arrays import (
    ZERO_HASH,
    BaseByteList,
    BaseBytes,
    Bytes4,
    Bytes32,
)
from lean_spec.spec.ssz.exceptions import SSZSerializationError, SSZTypeError, SSZValueError


class ByteList5(BaseByteList):
    """A bytelist with limit 5 for testing."""

    LIMIT = 5


class ByteList16(BaseByteList):
    """A bytelist with limit 16 for testing."""

    LIMIT = 16


class ModelVectors(BaseModel):
    """Pydantic model holding fixed-length byte arrays."""

    root: Bytes32
    key: Bytes4


class ModelLists(BaseModel):
    """Pydantic model holding a variable-length byte list."""

    payload: ByteList16


class TestBaseBytesConstruction:
    """Construction and coercion of fixed-length byte arrays."""

    def test_inheritance(self) -> None:
        """Concrete subclasses inherit from BaseBytes and stay bytes-compatible."""
        assert issubclass(Bytes32, BaseBytes)
        assert Bytes32.LENGTH == 32
        v = Bytes32(b"\x00" * 32)
        assert isinstance(v, Bytes32)
        assert isinstance(v, bytes)
        assert len(v) == 32

    @pytest.mark.parametrize(
        "input_value, expected",
        [
            (b"\x00\x01\x02\x03", b"\x00\x01\x02\x03"),
            (bytearray(b"\x00\x01\x02\x03"), b"\x00\x01\x02\x03"),
            ([0, 1, 2, 3], b"\x00\x01\x02\x03"),
            ((i for i in range(4)), b"\x00\x01\x02\x03"),
            ("00010203", b"\x00\x01\x02\x03"),
            ("0x00010203", b"\x00\x01\x02\x03"),
        ],
    )
    def test_coercion_from_supported_inputs(self, input_value: Any, expected: bytes) -> None:
        """Bytes, bytearray, iterables, generators, and hex strings all coerce to bytes."""
        v = Bytes4(input_value)
        assert bytes(v) == expected

    @pytest.mark.parametrize(
        "wrong_input, count",
        [
            (b"\x00\x01\x02", 3),
            ([0, 1, 2], 3),
            ("000102", 3),
        ],
    )
    def test_construction_with_wrong_length_raises(self, wrong_input: Any, count: int) -> None:
        """Inputs whose length doesn't match LENGTH raise with the exact element count."""
        with pytest.raises(
            SSZValueError,
            match=re.escape(f"Bytes4 requires exactly 4 bytes, got {count}"),
        ):
            Bytes4(wrong_input)

    @pytest.mark.parametrize("bad_input", [42, None, 1.5])
    def test_construction_with_non_coercible_input_raises(self, bad_input: Any) -> None:
        """Inputs outside the accepted union raise TypeError naming the offending type."""
        name = type(bad_input).__name__
        with pytest.raises(TypeError, match=re.escape(f"Cannot coerce {name} to bytes")):
            Bytes4(bad_input)

    def test_construction_without_length_attribute_raises(self) -> None:
        """Direct instantiation of the abstract base raises SSZTypeError."""
        with pytest.raises(SSZTypeError, match=re.escape("BaseBytes must define LENGTH")):
            BaseBytes(b"")

    def test_zero_factory(self) -> None:
        """The zero classmethod returns an instance of LENGTH zero bytes."""
        v = Bytes4.zero()
        assert isinstance(v, Bytes4)
        assert bytes(v) == b"\x00\x00\x00\x00"


class TestBaseBytesEquality:
    """Strict equality, inequality, and hashing of fixed-length byte arrays."""

    def test_same_type_equality(self) -> None:
        """Instances with the same value and type compare equal."""
        v1 = Bytes4(b"\x00\x01\x02\x03")
        v2 = Bytes4([0, 1, 2, 3])
        v3 = Bytes4("00010203")
        assert v1 == v2 == v3

    def test_same_type_inequality(self) -> None:
        """Instances with different values compare unequal."""
        v1 = Bytes4(b"\x00\x00\x00\x00")
        v2 = Bytes4(b"\x00\x00\x00\x01")
        assert v1 != v2

    @pytest.mark.parametrize("other", [b"\x00\x01\x02\x03", "string", 1.5, None, 42])
    def test_cross_type_equality_raises(self, other: Any) -> None:
        """Comparing with any non-BaseBytes value raises TypeError."""
        name = type(other).__name__
        with pytest.raises(
            TypeError,
            match=re.escape(f"Unsupported operand type(s) for ==: 'Bytes4' and '{name}'"),
        ):
            _ = Bytes4(b"\x00\x01\x02\x03") == other

    @pytest.mark.parametrize("other", [b"\x00\x01\x02\x03", "string", 1.5, None, 42])
    def test_cross_type_inequality_raises(self, other: Any) -> None:
        """Inequality with any non-BaseBytes value raises TypeError."""
        name = type(other).__name__
        with pytest.raises(
            TypeError,
            match=re.escape(f"Unsupported operand type(s) for !=: 'Bytes4' and '{name}'"),
        ):
            _ = Bytes4(b"\x00\x01\x02\x03") != other

    def test_hash_distinct_from_raw_bytes(self) -> None:
        """The hash binds the value to its concrete type, so equal raw bytes hash differently."""
        v = Bytes4(b"\x00\x01\x02\x03")
        assert hash(v) != hash(b"\x00\x01\x02\x03")

    def test_hash_same_for_equal_instances(self) -> None:
        """Equal instances of the same type produce the same hash."""
        v1 = Bytes4(b"\x00\x01\x02\x03")
        v2 = Bytes4([0, 1, 2, 3])
        v3 = Bytes4("00010203")
        assert hash(v1) == hash(v2) == hash(v3)


class TestBaseBytesOperations:
    """Repr, hex, iteration, indexing, ordering, and concatenation."""

    def test_repr(self) -> None:
        """The repr is the class name with the hex content in parentheses."""
        assert repr(Bytes4(b"\x00\x01\x02\x03")) == "Bytes4(00010203)"

    def test_hex(self) -> None:
        """The hex method returns the lowercase hex string."""
        assert Bytes4(b"\x00\x01\x02\x03").hex() == "00010203"

    def test_len_iter_getitem(self) -> None:
        """The instance supports len, iteration, and integer indexing."""
        v = Bytes4(b"\x00\x01\x02\x03")
        assert len(v) == 4
        assert list(iter(v)) == [0, 1, 2, 3]
        assert v[2] == 2

    def test_concatenation_returns_plain_bytes(self) -> None:
        """Concatenation of two instances returns plain bytes."""
        a = Bytes4(b"\x00\x00\x00\x01")
        b = Bytes4(b"\x00\x00\x00\x02")
        conc = a + b
        assert type(conc) is bytes
        assert conc == b"\x00\x00\x00\x01\x00\x00\x00\x02"

    def test_reverse_concatenation_returns_plain_bytes(self) -> None:
        """Concatenation with raw bytes on the left returns plain bytes."""
        a = Bytes4(b"\x00\x00\x00\x01")
        conc = b"\xff" + a
        assert type(conc) is bytes
        assert conc == b"\xff\x00\x00\x00\x01"

    def test_sort_lexicographic(self) -> None:
        """Instances sort lexicographically by byte content."""
        a = Bytes32(b"\x00" * 31 + b"\x01")
        b = Bytes32(b"\x00" * 31 + b"\x02")
        c = Bytes32(b"\xff" * 32)
        assert sorted([c, b, a]) == [a, b, c]

    def test_hashlib_compatibility(self) -> None:
        """An instance is usable wherever a bytes-like value is expected."""
        r = Bytes32(b"\x01" + b"\x00" * 31)
        digest = hashlib.sha256(r).digest()
        assert len(digest) == 32


class TestBaseBytesSSZ:
    """SSZ interface methods and serialization round-trip."""

    def test_is_fixed_size(self) -> None:
        """BaseBytes subclasses are always fixed-size."""
        assert Bytes32.is_fixed_size() is True

    def test_get_byte_length(self) -> None:
        """get_byte_length returns the declared LENGTH."""
        assert Bytes32.get_byte_length() == 32
        assert Bytes4.get_byte_length() == 4

    @pytest.mark.parametrize(
        "cls, payload",
        [
            (Bytes4, b"\x00\x01\x02\x03"),
            (Bytes32, b"\x11" * 32),
        ],
    )
    def test_encode_decode_roundtrip(self, cls: type[BaseBytes], payload: bytes) -> None:
        """BaseBytes round-trips through encode_bytes, decode_bytes, and stream serialization."""
        v = cls(payload)
        assert v.encode_bytes() == payload
        assert cls.decode_bytes(payload) == v

        buf = io.BytesIO()
        n = v.serialize(buf)
        assert n == len(payload)

        buf.seek(0)
        v2 = cls.deserialize(buf, len(payload))
        assert v == v2

    def test_deserialize_scope_mismatch_raises(self) -> None:
        """deserialize rejects a scope that doesn't match LENGTH."""
        buf = io.BytesIO(b"\x00\x01\x02\x03")
        with pytest.raises(
            SSZSerializationError,
            match=re.escape("Bytes4: expected 4 bytes, got 3"),
        ):
            Bytes4.deserialize(buf, 3)

    def test_deserialize_stream_truncation_raises(self) -> None:
        """deserialize detects when the stream ends before delivering scope bytes."""
        buf = io.BytesIO(b"\x00\x01")
        with pytest.raises(
            SSZSerializationError,
            match=re.escape("Bytes4: expected 4 bytes, got 2"),
        ):
            Bytes4.deserialize(buf, 4)


class TestBaseBytesPydantic:
    """Pydantic validation and JSON serialization for fixed-length byte arrays."""

    def test_accepts_typed_instances_and_supported_inputs(self) -> None:
        """Pydantic accepts existing instances built from hex strings or iterables."""
        m = ModelVectors(
            root=Bytes32("0x" + "11" * 32),
            key=Bytes4([0, 1, 2, 3]),
        )
        assert isinstance(m.root, Bytes32)
        assert isinstance(m.key, Bytes4)
        assert bytes(m.root) == b"\x11" * 32
        assert bytes(m.key) == b"\x00\x01\x02\x03"

    def test_json_serialization_to_hex(self) -> None:
        """Serialization uses 0x-prefixed lowercase hex for JSON output."""
        m = ModelVectors(
            root=Bytes32("0x" + "11" * 32),
            key=Bytes4([0, 1, 2, 3]),
        )
        dumped = m.model_dump()
        assert dumped["root"] == "0x" + "11" * 32
        assert dumped["key"] == "0x00010203"


class TestBaseByteListConstruction:
    """Construction and coercion of variable-length byte lists."""

    def test_inheritance(self) -> None:
        """Concrete subclasses carry the declared limit."""
        v = ByteList16(data=b"\x01\x02")
        assert isinstance(v, ByteList16)
        assert ByteList16.LIMIT == 16
        assert len(v.data) == 2

    @pytest.mark.parametrize(
        "input_value, expected",
        [
            (b"\x00\x01\x02\x03\x04", b"\x00\x01\x02\x03\x04"),
            (bytearray(b"\x00\x01\x02\x03\x04"), b"\x00\x01\x02\x03\x04"),
            ([0, 1, 2, 3, 4], b"\x00\x01\x02\x03\x04"),
            ("0001020304", b"\x00\x01\x02\x03\x04"),
            ("0x0001020304", b"\x00\x01\x02\x03\x04"),
        ],
    )
    def test_coercion_from_supported_inputs(self, input_value: Any, expected: bytes) -> None:
        """Bytes, bytearray, iterables, and hex strings all coerce to bytes."""
        v = ByteList5(data=input_value)
        assert v.data == expected
        assert len(v.data) == len(expected)

    def test_construction_over_limit_raises(self) -> None:
        """Input exceeding LIMIT raises with the exact size in the message."""
        with pytest.raises(
            SSZValueError,
            match=re.escape("ByteList5 exceeds limit of 5, got 6"),
        ):
            ByteList5(data=b"\x00" * 6)

    def test_construction_without_limit_attribute_raises(self) -> None:
        """Direct instantiation of the abstract base raises SSZTypeError."""
        with pytest.raises(SSZTypeError, match=re.escape("BaseByteList must define LIMIT")):
            BaseByteList(data=b"")


class TestBaseByteListEquality:
    """Strict equality, inequality, and hashing of variable-length byte lists."""

    def test_same_type_equality(self) -> None:
        """Instances with the same value compare equal."""
        v1 = ByteList16(data=b"\x00\x01\x02")
        v2 = ByteList16(data=b"\x00\x01\x02")
        assert v1 == v2

    def test_same_type_inequality(self) -> None:
        """Instances with different values compare unequal."""
        v1 = ByteList16(data=b"\x00")
        v2 = ByteList16(data=b"\x01")
        assert v1 != v2

    @pytest.mark.parametrize("other", [b"\x00\x01\x02", "string", 1.5, None, 42])
    def test_cross_type_equality_raises(self, other: Any) -> None:
        """Comparing with any non-BaseByteList value raises TypeError."""
        name = type(other).__name__
        with pytest.raises(
            TypeError,
            match=re.escape(f"Unsupported operand type(s) for ==: 'ByteList16' and '{name}'"),
        ):
            _ = ByteList16(data=b"\x00\x01\x02") == other

    @pytest.mark.parametrize("other", [b"\x00\x01\x02", "string", 1.5, None, 42])
    def test_cross_type_inequality_raises(self, other: Any) -> None:
        """Inequality with any non-BaseByteList value raises TypeError."""
        name = type(other).__name__
        with pytest.raises(
            TypeError,
            match=re.escape(f"Unsupported operand type(s) for !=: 'ByteList16' and '{name}'"),
        ):
            _ = ByteList16(data=b"\x00\x01\x02") != other

    def test_hash_includes_type(self) -> None:
        """Instances of different bytelist types with the same data hash differently."""
        v1 = ByteList5(data=b"\x00\x01")
        v2 = ByteList16(data=b"\x00\x01")
        assert hash(v1) != hash(v2)

    def test_hash_same_for_equal_instances(self) -> None:
        """Equal instances of the same type produce the same hash."""
        v1 = ByteList16(data=b"\x00\x01\x02")
        v2 = ByteList16(data=b"\x00\x01\x02")
        assert hash(v1) == hash(v2)


class TestBaseByteListOperations:
    """Repr, hex, bytes coercion, and concatenation."""

    def test_repr(self) -> None:
        """The repr is the class name with the hex content in parentheses."""
        assert repr(ByteList16(data=b"\x00\x01\x02")) == "ByteList16(000102)"

    def test_hex(self) -> None:
        """The hex method returns the lowercase hex string."""
        assert ByteList16(data=b"\x00\x01\x02").hex() == "000102"

    def test_bytes_dunder(self) -> None:
        """Calling bytes() on an instance returns the underlying bytes."""
        assert bytes(ByteList16(data=b"\x00\x01\x02")) == b"\x00\x01\x02"

    def test_concatenation_returns_plain_bytes(self) -> None:
        """Concatenation with a bytes-like value returns plain bytes."""
        v = ByteList16(data=b"\x00\x01\x02")
        conc = v + b"\x03\x04"
        assert type(conc) is bytes
        assert conc == b"\x00\x01\x02\x03\x04"

    def test_reverse_concatenation_returns_plain_bytes(self) -> None:
        """Concatenation with raw bytes on the left returns plain bytes."""
        v = ByteList16(data=b"\x00\x01")
        conc = b"\xff" + v
        assert type(conc) is bytes
        assert conc == b"\xff\x00\x01"


class TestBaseByteListSSZ:
    """SSZ interface methods and serialization round-trip."""

    def test_is_fixed_size(self) -> None:
        """BaseByteList subclasses are always variable-size."""
        assert ByteList16.is_fixed_size() is False

    def test_get_byte_length_raises(self) -> None:
        """get_byte_length raises a descriptive error for variable-size types."""
        with pytest.raises(
            SSZTypeError,
            match=re.escape("ByteList16: variable-size byte list has no fixed byte length"),
        ):
            ByteList16.get_byte_length()

    @pytest.mark.parametrize(
        "limit, data",
        [
            (0, b""),
            (1, b"\xaa"),
            (5, b"\x00\x01\x02\x03\x04"),
            (16, bytes(range(16))),
        ],
    )
    def test_encode_decode_roundtrip(self, limit: int, data: bytes) -> None:
        """ByteList round-trips through encode_bytes, decode_bytes, and stream serialization."""

        class TestByteList(BaseByteList):
            LIMIT = limit

        x = TestByteList(data=data)
        assert x.encode_bytes() == data
        assert TestByteList.decode_bytes(data) == x

        buf = io.BytesIO()
        n = x.serialize(buf)
        assert n == len(data)

        buf.seek(0)
        y = TestByteList.deserialize(buf, len(data))
        assert y == x

    def test_deserialize_negative_scope_raises(self) -> None:
        """deserialize rejects a negative scope."""
        buf = io.BytesIO(b"")
        with pytest.raises(
            SSZSerializationError,
            match=re.escape("ByteList16: negative scope"),
        ):
            ByteList16.deserialize(buf, -1)

    def test_deserialize_over_limit_raises(self) -> None:
        """deserialize rejects a scope exceeding LIMIT."""
        buf = io.BytesIO(b"\x00" * 6)
        with pytest.raises(
            SSZValueError,
            match=re.escape("ByteList5 exceeds limit of 5, got 6"),
        ):
            ByteList5.deserialize(buf, 6)

    def test_deserialize_stream_truncation_raises(self) -> None:
        """deserialize detects when the stream ends before delivering scope bytes."""
        buf = io.BytesIO(b"\x00\x01")
        with pytest.raises(
            SSZSerializationError,
            match=re.escape("ByteList16: expected 3 bytes, got 2"),
        ):
            ByteList16.deserialize(buf, 3)


class TestBaseByteListPydantic:
    """Pydantic validation and JSON serialization for variable-length byte lists."""

    def test_accepts_valid_input(self) -> None:
        """Pydantic accepts construction with bytes within LIMIT."""
        data = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        m = ModelLists(payload=ByteList16(data=data))
        assert isinstance(m.payload, ByteList16)
        assert m.payload.encode_bytes() == data

    def test_rejects_oversized_input(self) -> None:
        """Pydantic rejects data exceeding LIMIT via SSZValueError."""
        with pytest.raises(SSZValueError):
            ModelLists(payload=ByteList16(data=bytes(range(17))))

    def test_json_serialization_to_hex(self) -> None:
        """JSON-mode serialization renders the data field as a 0x-prefixed hex string."""
        data = bytes.fromhex("0001020304")
        m = ModelLists(payload=ByteList16(data=data))
        dumped = m.model_dump(mode="json")
        assert dumped["payload"]["data"] == "0x0001020304"


def test_zero_hash_constant() -> None:
    """The module-level ZERO_HASH is a 32-byte zero-filled Bytes32 instance."""
    assert isinstance(ZERO_HASH, Bytes32)
    assert bytes(ZERO_HASH) == b"\x00" * 32


def test_json_dumpable_via_hex() -> None:
    """Byte instances are JSON-dumpable when pre-encoded to hex strings."""
    obj = {
        "root": Bytes32(b"\x11" * 32).hex(),
        "key": Bytes4(b"\x00\x01\x02\x03").hex(),
        "payload": ByteList5(data=b"\x00\x01\x02").hex(),
    }
    assert json.loads(json.dumps(obj)) == obj
