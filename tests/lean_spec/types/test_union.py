from __future__ import annotations

import io
from typing import Any, cast
from typing import Type as PyType

import pytest
from pydantic import ValidationError, create_model

from lean_spec.types.collections import List, Vector
from lean_spec.types.container import Container
from lean_spec.types.ssz_base import SSZType
from lean_spec.types.uint import Uint8, Uint16, Uint32
from lean_spec.types.union import Union as SSZUnion


def u_fn(*opts: Any) -> Any:
    """Build a specialized SSZUnion using __class_getitem__ (mypy-friendly)."""
    return SSZUnion.__class_getitem__(tuple(opts))


def ll(elem: Any, limit: int) -> Any:
    """Build a specialized List[elem, limit] without [] syntax (mypy-friendly)."""
    return List.__class_getitem__((elem, limit))


def vv(elem: Any, length: int) -> Any:
    """Build a specialized Vector[elem, length] without [] syntax (mypy-friendly)."""
    return Vector.__class_getitem__((elem, length))


class SingleField(Container):
    """Tiny fixed-size container."""

    A: Uint8


class FixedPair(Container):
    """Another small container, to test duplicate option types in unions."""

    a: Uint8
    b: Uint16


class VarPair(Container):
    """Variable-size container (offset present) to test nested composites."""

    a: Uint8
    # Note: this annotation uses a runtime-parameterized SSZ type;
    # mypy does not understand it as a valid type. The Container metaclass
    # needs the concrete SSZ type here though, so we keep it and ignore the type check.
    b: ll(Uint16, 8)  # type: ignore[valid-type]


def test_class_getitem_builds_specialized_type() -> None:
    u1 = u_fn(Uint16)
    u2 = u_fn(None, Uint16, Uint32)
    assert u1 is u_fn(Uint16)  # caching
    assert u1 is not u2
    assert u1.options() == (Uint16,)
    assert u2.options() == (None, Uint16, Uint32)
    # Union is always variable-size overall
    assert not u1.is_fixed_size()
    assert not u2.is_fixed_size()


def test_class_getitem_rejects_bad_options() -> None:
    # Only option 0 may be None
    with pytest.raises(TypeError, match="Only option 0 may be None"):
        _ = u_fn(Uint16, None)
    # At least one option
    with pytest.raises(TypeError, match="at least one option"):
        SSZUnion.__class_getitem__(())  # explicit call with empty tuple
    # None at 0 must have another non-none option
    with pytest.raises(TypeError, match="must have at least one non-None option"):
        _ = u_fn(None)


def test_constructor_success() -> None:
    u = u_fn(None, Uint16, Uint32)
    assert u(selector=0, value=None).selector == 0
    assert u(selector=1, value=Uint16(0xBEEF)).value == Uint16(0xBEEF)
    # coercion from plain int works
    assert u(selector=2, value=0xAABBCCDD).value == Uint32(0xAABBCCDD)


def test_constructor_errors() -> None:
    u = u_fn(None, Uint16, Uint32)
    with pytest.raises(ValueError, match="Invalid selector"):
        u(selector=3, value=None)
    with pytest.raises(TypeError, match="value must be None"):
        u(selector=0, value=Uint16(1))
    # Wrong inner value type that cannot be coerced
    with pytest.raises(TypeError):
        u(selector=1, value="not-an-int")


def test_pydantic_validation_ok() -> None:
    u = u_fn(None, Uint16, Uint32)
    model = create_model("M", v=(u, ...))

    # Instance passes through
    inst = u(selector=1, value=Uint16(0xAA55))
    m = cast(Any, model(v=inst))
    assert isinstance(m.v, u)
    assert m.v.value == Uint16(0xAA55)

    # Mapping form: selector + value (coerced)
    m2 = cast(Any, model(v={"selector": 2, "value": 0xDEADBEEF}))
    assert isinstance(m2.v, u)
    assert m2.v.selector == 2
    assert m2.v.value == Uint32(0xDEADBEEF)

    # None arm
    m3 = cast(Any, model(v={"selector": 0, "value": None}))
    assert m3.v.value is None


def test_pydantic_validation_errors() -> None:
    u = u_fn(None, Uint16, Uint32)
    model = create_model("M", v=(u, ...))
    with pytest.raises(ValidationError):
        model(v={"selector": 9, "value": 0})
    with pytest.raises(ValidationError):
        model(v={"selector": 0, "value": 1})
    with pytest.raises(ValidationError):
        model(v=["not-a-mapping"])

    # More bad mappings: missing keys and wrong selector type
    with pytest.raises(ValidationError):
        model(v={"selector": 1})  # missing value
    with pytest.raises(ValidationError):
        model(v={"value": 123})  # missing selector
    with pytest.raises(ValidationError):
        model(v={"selector": "1", "value": 123})  # selector must be int


@pytest.mark.parametrize(
    "u_type, selector, value, expected_hex",
    [
        (u_fn(Uint16), 0, Uint16(0xAABB), "00bbaa"),
        (u_fn(Uint16, Uint32), 0, Uint16(0xAABB), "00bbaa"),
        (u_fn(None, Uint16, Uint32), 0, None, "00"),
        (u_fn(None, Uint16, Uint32), 1, Uint16(0xAABB), "01bbaa"),
        (u_fn(Uint16, Uint32), 1, Uint32(0xDEADBEEF), "01efbeadde"),
        (u_fn(Uint16, Uint32, Uint8, ll(Uint16, 8)), 2, Uint8(0xAA), "02aa"),
        (u_fn(SingleField, SingleField), 1, SingleField(A=Uint8(0xAB)), "01ab"),
    ],
)
def test_union_serialize_matches_reference(
    u_type: PyType[Any],
    selector: int,
    value: Any,
    expected_hex: str,
) -> None:
    inst = u_type(selector=selector, value=value)
    # encode_bytes
    encoded = inst.encode_bytes()
    assert encoded.hex() == expected_hex

    # serialize(stream)
    stream = io.BytesIO()
    n = inst.serialize(stream)
    stream.seek(0)
    assert stream.read().hex() == expected_hex
    assert n == len(bytes.fromhex(expected_hex))

    # decode_bytes / deserialize
    decoded = u_type.decode_bytes(bytes.fromhex(expected_hex))
    assert decoded.selector == selector
    assert decoded.value == value


def test_union_with_nested_composites_roundtrip() -> None:
    # Union including vector, containers and list
    u = u_fn(vv(Uint8, 3), SingleField, VarPair, FixedPair, Uint16)

    # selector = 2 (VarPair)
    elem_list = ll(Uint16, 8)([1, 2, 3])
    vp = VarPair(a=Uint8(0xAB), b=elem_list)
    inst = u(selector=2, value=vp)
    # round-trip
    encoded = inst.encode_bytes()
    dec = u.decode_bytes(encoded)
    assert dec.selector == 2
    assert dec.value == vp

    # selector = 0 (Vector[Uint8,3])
    v = vv(Uint8, 3)([9, 8, 7])
    inst2 = u(selector=0, value=v)
    assert u.decode_bytes(inst2.encode_bytes()) == inst2

    # selector = 4 (Uint16)
    inst3 = u(selector=4, value=Uint16(0xBEEF))
    assert u.decode_bytes(inst3.encode_bytes()) == inst3


def test_deserialize_errors() -> None:
    u = u_fn(None, Uint16)
    # scope < 1
    with pytest.raises(ValueError, match="Scope too small"):
        u.deserialize(io.BytesIO(b""), 0)
    # selector out of range
    with pytest.raises(ValueError, match="out of range"):
        u.deserialize(io.BytesIO(b"\x02"), 1)
    # None arm must have no payload
    with pytest.raises(ValueError, match="None arm must have no payload"):
        u.deserialize(io.BytesIO(b"\x00\xff"), 2)
    # Non-none arm, but not enough scope to satisfy inner (Uint16 needs 2 bytes)
    # The implementation should surface this as an IOError at the Union level.
    with pytest.raises(IOError):
        u.deserialize(io.BytesIO(b"\x01\xaa"), 2)


def test_repr_contains_selector_and_value() -> None:
    u = u_fn(Uint16, Uint32)
    inst = u(selector=0, value=Uint16(3))
    r = repr(inst)
    assert "selector=0" in r
    assert "Uint16(3)" in r


def test_cache_identity_and_distinctness() -> None:
    # Identity: same parameterization reuses the cached type
    u1 = u_fn(Uint16, Uint32)
    u2 = u_fn(Uint16, Uint32)
    assert u1 is u2

    # Distinctness: different order or options -> different type
    u3 = u_fn(Uint32, Uint16)
    assert u1 is not u3
    assert u1.options() == (Uint16, Uint32)
    assert u3.options() == (Uint32, Uint16)


def test_selected_type_sanity() -> None:
    u = u_fn(None, Uint16, Uint32)
    u0 = u(selector=0, value=None)
    u1 = u(selector=1, value=Uint16(5))
    u2 = u(selector=2, value=Uint32(6))
    assert u0.selected_type is None
    assert u1.selected_type is Uint16
    assert u2.selected_type is Uint32


def test_equality_and_hashing() -> None:
    u = u_fn(Uint16, Uint32)
    a = u(selector=0, value=Uint16(10))
    b = u(selector=0, value=Uint16(10))
    c = u(selector=1, value=Uint32(10))
    # same specialized type, same selector/value -> equal & same hash
    assert a == b
    assert hash(a) == hash(b)
    # different selector -> not equal
    assert a != c
    # usable in sets/dicts
    s = {a, b, c}
    assert len(s) == 2
    d = {a: "A", c: "C"}
    assert d[a] == "A"
    assert d[c] == "C"


def test_max_options_boundary_and_too_many() -> None:
    # Exactly 128 options is allowed
    opts_ok = tuple([Uint8] * 128)
    u_ok = SSZUnion.__class_getitem__(opts_ok)
    assert isinstance(u_ok, type)
    assert issubclass(u_ok, SSZUnion)
    assert len(u_ok.options()) == 128

    # 129 options should fail
    opts_bad = tuple([Uint8] * 129)
    with pytest.raises(TypeError, match="at most 128 options"):
        _ = SSZUnion.__class_getitem__(opts_bad)


def test_invalid_option_type_rejected() -> None:
    # Create a fake type missing SSZType protocol methods
    class NotSSZ:
        pass

    with pytest.raises(TypeError, match="must be an SSZType-like"):
        _ = SSZUnion.__class_getitem__((cast(PyType[SSZType], NotSSZ),))  # wrong kind of type


def test_options_and_is_fixed_size_helpers() -> None:
    u = u_fn(Uint16)
    assert u.options() == (Uint16,)
    assert not u.is_fixed_size()
