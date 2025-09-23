# flake8: noqa E501
import io
import hashlib
import json
import pytest

from pydantic import BaseModel
from typing import Any, Type

from lean_spec.types.byte_arrays import (
    ByteList64,
    ByteList256,
    Bytes1,
    Bytes4,
    Bytes8,
    Bytes32,
    Bytes48,
    Bytes96,
    BaseBytes,
    ByteListBase,
)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def test_bytes_inheritance_ok() -> None:
    # Test that our concrete types properly inherit from BaseBytes
    assert issubclass(Bytes32, BaseBytes)
    assert Bytes32.LENGTH == 32
    v = Bytes32(b"\x00" * 32)
    assert isinstance(v, Bytes32)
    assert isinstance(v, bytes)  # Should also be a bytes object
    assert len(v) == 32


def test_bytelist_inheritance_ok() -> None:
    # Test that our concrete ByteList types properly inherit from ByteListBase
    assert issubclass(ByteList64, ByteListBase)
    assert ByteList64.LIMIT == 64
    v = ByteList64(data=b"\x01\x02")
    assert isinstance(v, ByteList64)
    assert len(v) == 2


@pytest.mark.parametrize(
    "value,expected",
    [
        (b"\x00\x01\x02\x03", b"\x00\x01\x02\x03"),
        (bytearray(b"\x00\x01\x02\x03"), b"\x00\x01\x02\x03"),
        ([0, 1, 2, 3], b"\x00\x01\x02\x03"),
        ((i for i in range(4)), b"\x00\x01\x02\x03"),
        ("00010203", b"\x00\x01\x02\x03"),
        ("0x00010203", b"\x00\x01\x02\x03"),
    ],
)
def test_bytevector_coercion(value: Any, expected: bytes) -> None:
    v = Bytes4(value)
    assert bytes(v) == expected


def test_bytevector_wrong_length_raises() -> None:
    with pytest.raises(ValueError):
        Bytes4(b"\x00\x01\x02")  # 3 != 4
    with pytest.raises(ValueError):
        Bytes4([0, 1, 2])  # 3 != 4
    with pytest.raises(ValueError):
        Bytes4("000102")  # 3 != 4 (hex nibbles -> 3 bytes)


@pytest.mark.parametrize(
    "value,expected",
    [
        (b"\x00\x01\x02\x03\x04", b"\x00\x01\x02\x03\x04"),
        ([0, 1, 2, 3, 4], b"\x00\x01\x02\x03\x04"),
        ("0001020304", b"\x00\x01\x02\x03\x04"),
    ],
)
def test_bytelist_coercion(value: Any, expected: bytes) -> None:
    # Use a ByteList with limit 5 for testing
    class ByteList5(ByteListBase):
        LIMIT = 5

    v = ByteList5(data=value)
    assert bytes(v) == expected
    assert len(v) == len(expected)


def test_bytelist_over_limit_raises() -> None:
    # Test with ByteList64 that has limit 64
    with pytest.raises(ValueError):
        ByteList64(data=b"\x00" * 65)  # Over the limit


def test_is_fixed_size_flags() -> None:
    assert Bytes32.is_fixed_size() is True
    assert ByteList64.is_fixed_size() is False


def test_len_iter_getitem_repr_hash_eq() -> None:
    v1 = Bytes4(b"\x00\x01\x02\x03")
    v2 = Bytes4([0, 1, 2, 3])
    v3 = Bytes4("00010203")
    assert len(v1) == 4  # ByteVector length equals type-level constant
    assert list(iter(v1)) == [0, 1, 2, 3]
    assert v1[2] == 2
    assert repr(v1).startswith("Bytes4(")
    assert v1 == v2 == v3
    assert hash(v1) == hash(v2) == hash(v3)


def test_hex_and_ordering() -> None:
    a = Bytes4(b"\x00\x00\x00\x01")
    b = Bytes4(b"\x00\x00\x00\x02")
    assert a.hex() == "00000001"
    assert b.hex() == "00000002"
    # Ordering enabled via __lt__
    assert sorted([b, a]) == [a, b]


def test_bytes_dunder_and_concat_and_rconcat() -> None:
    a = Bytes4(b"\x00\x00\x00\x01")
    b = Bytes4(b"\x00\x00\x00\x02")
    # __bytes__
    assert bytes(a) == b"\x00\x00\x00\x01"
    # __add__ returns raw bytes
    conc = a + b
    assert isinstance(conc, (bytes, bytearray))
    assert conc == b"\x00\x00\x00\x01\x00\x00\x00\x02"
    # __radd__
    conc2 = b"\xff" + a
    assert conc2 == b"\xff\x00\x00\x00\x01"


def test_hashlib_accepts_bytes32_via_add() -> None:
    r1 = Bytes32(b"\x01" + b"\x00" * 31)
    r2 = Bytes32(b"\x02" + b"\x00" * 31)
    # a + b -> bytes, usable by hashlib.sha256
    h = hashlib.sha256(r1 + r2).digest()
    assert isinstance(h, bytes)
    assert len(h) == 32


@pytest.mark.parametrize(
    "Typ, payload",
    [
        (Bytes1, b"\xaa"),
        (Bytes4, b"\x00\x01\x02\x03"),
        (Bytes8, b"\x00\x01\x02\x03\x04\x05\x06\x07"),
        (Bytes32, b"\x11" * 32),
        (Bytes48, bytes(range(48))),
        (Bytes96, bytes(range(96))),
    ],
)
def test_encode_decode_roundtrip_vector(Typ: Type[BaseBytes], payload: bytes) -> None:
    v = Typ(payload)
    assert v.encode_bytes() == payload
    assert Typ.decode_bytes(payload) == v

    # serialize/deserialize via IO[bytes]
    buf = io.BytesIO()
    n = v.serialize(buf)
    assert n == len(payload)
    buf.seek(0)
    v2 = Typ.deserialize(buf, len(payload))
    assert v == v2


def test_vector_deserialize_scope_mismatch_raises() -> None:
    v = Bytes4(b"\x00\x01\x02\x03")
    buf = io.BytesIO(v.encode_bytes())
    with pytest.raises(ValueError):
        Bytes4.deserialize(buf, 3)  # wrong scope


@pytest.mark.parametrize(
    "limit,data",
    [
        (0, b""),
        (1, b"\xaa"),
        (5, b"\x00\x01\x02\x03\x04"),
    ],
)
def test_encode_decode_roundtrip_list(limit: int, data: bytes) -> None:
    # Create a test-specific ByteList class with the required limit
    class TestByteList(ByteListBase):
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


def test_list_deserialize_over_limit_raises() -> None:
    class TestByteList2(ByteListBase):
        LIMIT = 2

    buf = io.BytesIO(b"\x00\x01\x02")
    with pytest.raises(ValueError):
        TestByteList2.deserialize(buf, 3)


def test_list_deserialize_short_stream_raises() -> None:
    class TestByteList10(ByteListBase):
        LIMIT = 10

    buf = io.BytesIO(b"\x00\x01")
    with pytest.raises(IOError):
        TestByteList10.deserialize(buf, 3)  # stream too short


class ModelVectors(BaseModel):
    root: Bytes32
    key: Bytes4


# Create test ByteList16 for the ModelLists test
class ByteList16(ByteListBase):
    LIMIT = 16


class ModelLists(BaseModel):
    payload: ByteList16


def test_pydantic_accepts_various_inputs_for_vectors() -> None:
    m = ModelVectors(
        root=Bytes32("0x" + "11" * 32),
        key=Bytes4([0, 1, 2, 3]),
    )
    assert isinstance(m.root, Bytes32)
    assert isinstance(m.key, Bytes4)
    assert bytes(m.root) == b"\x11" * 32
    assert bytes(m.key) == b"\x00\x01\x02\x03"

    # serializer returns string representation in model_dump()
    dumped = m.model_dump()
    assert isinstance(dumped["root"], str)
    assert dumped["root"] == "11" * 32  # hex string without 0x prefix
    assert dumped["key"] == "00010203"  # hex string representation


def test_pydantic_validates_vector_lengths() -> None:
    with pytest.raises(ValueError):
        ModelVectors(root=b"\x11" * 31, key=b"\x00\x01\x02\x03")  # too short
    with pytest.raises(ValueError):
        ModelVectors(root=b"\x11" * 33, key=b"\x00\x01\x02\x03")  # too long
    with pytest.raises(ValueError):
        ModelVectors(root=b"\x11" * 32, key=b"\x00\x01\x02")  # key too short


def test_pydantic_accepts_and_serializes_bytelist() -> None:
    m = ModelLists(payload=ByteList16(data="0x000102030405060708090a0b0c0d0e0f"))

    assert isinstance(m.payload, ByteList16)
    assert m.payload.encode_bytes() == bytes(range(16))

    dumped = m.model_dump()
    payload = dumped["payload"]

    # ByteList serializes as dict with 'data' field
    assert isinstance(payload, dict)
    assert "data" in payload
    assert payload["data"] == bytes(range(16))

    # Round-trip back through Pydantic using the dumped Python object
    decoded = ModelLists.model_validate(dumped)
    assert decoded.payload.encode_bytes() == bytes(range(16))


def test_pydantic_bytelist_limit_enforced() -> None:
    with pytest.raises(ValueError):
        ModelLists(payload=bytes(range(17)))  # over limit


def test_add_repr_equality_hash_do_not_crash_on_aliases() -> None:
    a = Bytes32(b"\xaa" * 32)
    b = Bytes32("aa" * 32)
    c = Bytes32(bytearray(b"\xaa" * 32))
    assert a == b == c
    assert hash(a) == hash(b) == hash(c)
    assert repr(a).startswith("Bytes32(")
    # Addition returns bytes
    assert isinstance(a + b, (bytes, bytearray))
    assert isinstance(b"\x00" + a, (bytes, bytearray))


def test_sorted_bytes32_list_is_lexicographic_on_bytes() -> None:
    a = Bytes32(b"\x00" * 31 + b"\x01")
    b = Bytes32(b"\x00" * 31 + b"\x02")
    c = Bytes32(b"\xff" * 32)
    arr = [c, b, a]
    s = sorted(arr)
    assert s == [a, b, c]


def test_json_like_dump_of_vectors_lists() -> None:
    # Create test ByteList5 for this test
    class ByteList5(ByteListBase):
        LIMIT = 5

    # Ensure users can dump simple object structures to JSON by pre-encoding to hex.
    obj = {
        "root": Bytes32(b"\x11" * 32).hex(),
        "sig": Bytes96(bytes(range(96))).hex(),
        "payload": ByteList5(data=b"\x00\x01\x02\x03\x04").hex(),
    }
    # strings are JSON-serializable
    assert json.loads(json.dumps(obj)) == obj


def test_bytelist_hex_and_concat_behaviour_like_vector() -> None:
    class ByteList8(ByteListBase):
        LIMIT = 8

    x = ByteList8(data="0x00010203")
    y = ByteList8(data=[4, 5])
    # __add__ returns bytes
    conc = x + y
    assert conc == b"\x00\x01\x02\x03\x04\x05"
    # __radd__
    conc2 = b"\xff" + x
    assert conc2 == b"\xff\x00\x01\x02\x03"
    # hex via bytes().hex() or .encode_bytes().hex()
    assert x.encode_bytes().hex() == "00010203"
