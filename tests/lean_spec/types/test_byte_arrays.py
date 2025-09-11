# flake8: noqa E501
import io
import hashlib
import json
import pytest

from pydantic import BaseModel
from typing import Any, Type

from lean_spec.types.byte_arrays import (
    ByteVector,
    ByteList,
    Bytes1,
    Bytes4,
    Bytes8,
    Bytes32,
    Bytes48,
    Bytes96,
    ByteVectorBase,
    ByteListBase,
)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def test_bytevector_factory_ok() -> None:
    B7 = ByteVector.__class_getitem__(7)
    assert issubclass(B7, ByteVectorBase)
    assert B7.LENGTH == 7
    v = B7(b"\x00" * 7)
    assert isinstance(v, B7)
    assert len(v) == 7


def test_bytevector_factory_bad_len_type() -> None:
    with pytest.raises(TypeError):
        # wrong type for N
        ByteVector.__class_getitem__("32")  # type: ignore[arg-type]


def test_bytevector_factory_negative() -> None:
    with pytest.raises(TypeError):
        ByteVector.__class_getitem__(-1)


def test_bytelist_factory_ok() -> None:
    L9 = ByteList.__class_getitem__(9)
    assert issubclass(L9, ByteListBase)
    assert L9.LIMIT == 9
    v = L9(b"\x01\x02")
    assert isinstance(v, L9)
    assert len(v) == 2


def test_bytelist_factory_bad_len_type() -> None:
    with pytest.raises(TypeError):
        ByteList.__class_getitem__(object())  # type: ignore[arg-type]


def test_bytelist_factory_negative() -> None:
    with pytest.raises(TypeError):
        ByteList.__class_getitem__(-5)


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
    L5 = ByteList.__class_getitem__(5)
    v = L5(value)
    assert bytes(v) == expected
    assert len(v) == len(expected)


def test_bytelist_over_limit_raises() -> None:
    L5 = ByteList.__class_getitem__(5)
    with pytest.raises(ValueError):
        L5(b"\x00" * 6)


def test_is_fixed_size_flags() -> None:
    assert Bytes32.is_fixed_size() is True
    L7 = ByteList.__class_getitem__(7)
    assert L7.is_fixed_size() is False


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
def test_encode_decode_roundtrip_vector(Typ: Type[ByteVectorBase], payload: bytes) -> None:
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
    L = ByteList.__class_getitem__(limit)
    x = L(data)
    assert x.encode_bytes() == data
    assert L.decode_bytes(data) == x

    buf = io.BytesIO()
    n = x.serialize(buf)
    assert n == len(data)
    buf.seek(0)
    y = L.deserialize(buf, len(data))
    assert y == x


def test_list_deserialize_over_limit_raises() -> None:
    L = ByteList.__class_getitem__(2)
    buf = io.BytesIO(b"\x00\x01\x02")
    with pytest.raises(ValueError):
        L.deserialize(buf, 3)


def test_list_deserialize_short_stream_raises() -> None:
    L = ByteList.__class_getitem__(10)
    buf = io.BytesIO(b"\x00\x01")
    with pytest.raises(IOError):
        L.deserialize(buf, 3)  # stream too short


class ModelVectors(BaseModel):
    root: Bytes32
    key: Bytes4


class ModelLists(BaseModel):
    payload: ByteList[16]  # type: ignore


def test_pydantic_accepts_various_inputs_for_vectors() -> None:
    m = ModelVectors(
        root="0x" + "11" * 32,
        key=[0, 1, 2, 3],
    )
    assert isinstance(m.root, Bytes32)
    assert isinstance(m.key, Bytes4)
    assert bytes(m.root) == b"\x11" * 32
    assert bytes(m.key) == b"\x00\x01\x02\x03"

    # serializer returns raw bytes in model_dump()
    dumped = m.model_dump()
    assert isinstance(dumped["root"], (bytes, bytearray))
    assert dumped["root"] == b"\x11" * 32
    assert dumped["key"] == b"\x00\x01\x02\x03"


def test_pydantic_validates_vector_lengths() -> None:
    with pytest.raises(ValueError):
        ModelVectors(root=b"\x11" * 31, key=b"\x00\x01\x02\x03")  # too short
    with pytest.raises(ValueError):
        ModelVectors(root=b"\x11" * 33, key=b"\x00\x01\x02\x03")  # too long
    with pytest.raises(ValueError):
        ModelVectors(root=b"\x11" * 32, key=b"\x00\x01\x02")  # key too short


def test_pydantic_accepts_and_serializes_bytelist() -> None:
    m = ModelLists(payload="0x000102030405060708090a0b0c0d0e0f")

    # mypy does not accept a dynamic specialization directly in isinstance;
    # bind it to a Type[Any] first.
    BL16: Type[Any] = ByteList.__class_getitem__(16)
    assert isinstance(m.payload, BL16)

    assert m.payload.encode_bytes() == bytes(range(16))

    dumped = m.model_dump()
    payload = dumped["payload"]

    # Accept any bytes-like object
    assert isinstance(payload, (bytes, bytearray, memoryview))
    assert bytes(payload) == bytes(range(16))

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
    # Ensure users can dump simple object structures to JSON by pre-encoding to hex.
    obj = {
        "root": Bytes32(b"\x11" * 32).hex(),
        "sig": Bytes96(bytes(range(96))).hex(),
        "payload": ByteList.__class_getitem__(5)(b"\x00\x01\x02\x03\x04").hex(),
    }
    # strings are JSON-serializable
    assert json.loads(json.dumps(obj)) == obj


def test_bytelist_hex_and_concat_behaviour_like_vector() -> None:
    L = ByteList.__class_getitem__(8)
    x = L("0x00010203")
    y = L([4, 5])
    # __add__ returns bytes
    conc = x + y
    assert conc == b"\x00\x01\x02\x03\x04\x05"
    # __radd__
    conc2 = b"\xff" + x
    assert conc2 == b"\xff\x00\x01\x02\x03"
    # hex via bytes().hex() or .encode_bytes().hex()
    assert x.encode_bytes().hex() == "00010203"
