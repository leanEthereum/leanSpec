"""Tests for the SSZ Container base class."""

import io

import pytest

from lean_spec.spec.ssz.collections import SSZList
from lean_spec.spec.ssz.container import Container
from lean_spec.spec.ssz.exceptions import SSZSerializationError, SSZTypeError
from lean_spec.spec.ssz.uint import Uint8, Uint16, Uint32, Uint64


class Uint16List4(SSZList[Uint16]):
    """A list with up to 4 Uint16 values for variable-field testing."""

    LIMIT = 4


class TwoUint64(Container):
    """Two fixed-size Uint64 fields, total width 16 bytes."""

    a: Uint64
    b: Uint64


class TwoVar(Container):
    """Two variable-size list fields, total width is dynamic."""

    a: Uint16List4
    b: Uint16List4


class Mixed(Container):
    """Interleaved fixed and variable fields covering the canonical mixed shape."""

    a: Uint64
    b: Uint16List4
    c: Uint32
    d: Uint16List4


class OneVar(Container):
    """Single variable-size field, exercises the single-offset branch."""

    a: Uint16List4


class InnerFixed(Container):
    """Inner fixed-size container nested inside another container."""

    x: Uint64
    y: Uint64


class OuterFixedNested(Container):
    """Outer fixed-size container that holds a fixed-size container as a field."""

    z: Uint64
    inner: InnerFixed


class InnerVar(Container):
    """Inner variable-size container with one variable field."""

    a: Uint64
    b: Uint16List4


class OuterVarNested(Container):
    """Outer container that holds a variable-size container as a field."""

    head: Uint64
    inner: InnerVar


class Attestation(Container):
    """Parent container with a fixed slot and a variable data list."""

    slot: Uint64
    data: Uint16List4


class SignedAttestation(Attestation):
    """Subclass appending a signature field after the parent fields."""

    signature: Uint64


class EmptyContainer(Container):
    """Zero-field container, exercises the all-fixed sum over an empty iterator."""


class OneByte(Container):
    """Smallest non-empty fixed container, used for hex helpers."""

    a: Uint8


class TestFixedContainer:
    """Fixed-size container metadata, encoding, and roundtrip behavior."""

    def test_is_fixed_size_true(self) -> None:
        """A container of only fixed-size fields reports as fixed-size."""
        assert TwoUint64.is_fixed_size() is True

    def test_get_byte_length_sums_field_widths(self) -> None:
        """The fixed byte width is the sum of each field's byte width."""
        assert TwoUint64.get_byte_length() == 16

    def test_serialize_writes_little_endian_fields(self) -> None:
        """Encoding concatenates each field's little-endian bytes in order."""
        encoded = TwoUint64(a=Uint64(1), b=Uint64(2)).encode_bytes()
        assert encoded == b"\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"

    @pytest.mark.parametrize(
        ("a", "b"),
        [
            pytest.param(0, 0, id="edge_zero"),
            pytest.param(1, 2, id="small"),
            pytest.param(0xDEADBEEF, 0xCAFEBABE, id="medium"),
            pytest.param(2**64 - 1, 2**64 - 1, id="large"),
        ],
    )
    def test_roundtrip_preserves_value(self, a: int, b: int) -> None:
        """Encoding then decoding recovers the original fixed container exactly."""
        original = TwoUint64(a=Uint64(a), b=Uint64(b))
        assert TwoUint64.decode_bytes(original.encode_bytes()) == original

    def test_empty_container_has_zero_byte_length(self) -> None:
        """A container with no fields has a fixed byte length of zero."""
        assert EmptyContainer.is_fixed_size() is True
        assert EmptyContainer.get_byte_length() == 0
        assert EmptyContainer().encode_bytes() == b""


class TestVariableContainer:
    """All-variable container shape and metadata."""

    def test_is_fixed_size_false(self) -> None:
        """A container with only variable-size fields reports as not fixed-size."""
        assert TwoVar.is_fixed_size() is False

    def test_get_byte_length_raises(self) -> None:
        """A variable-size container has no fixed byte length and must raise."""
        with pytest.raises(SSZTypeError) as exc_info:
            TwoVar.get_byte_length()
        assert exc_info.value.args[0] == "TwoVar: variable-size container has no fixed byte length"

    def test_all_variable_roundtrip(self) -> None:
        """A container of two variable lists roundtrips through encode then decode."""
        original = TwoVar(
            a=Uint16List4(data=[Uint16(0x1234), Uint16(0x5678)]),
            b=Uint16List4(data=[Uint16(0x9ABC)]),
        )
        # Fixed-part width is 8 bytes for two Uint32 offsets.
        # First offset is 8, second offset is 12 because the first payload spans 4 bytes.
        expected = bytes.fromhex("080000000c00000034127856bc9a")
        assert original.encode_bytes() == expected
        assert TwoVar.decode_bytes(expected) == original


class TestOneVariableField:
    """Edge case where the variable-field list contains exactly one entry."""

    def test_one_variable_field_roundtrip(self) -> None:
        """A container with a single variable field encodes one offset and the payload."""
        original = OneVar(a=Uint16List4(data=[Uint16(0x1234)]))
        # Fixed part is one offset of 4 bytes pointing to 4, then the payload.
        assert original.encode_bytes() == bytes.fromhex("040000003412")
        assert OneVar.decode_bytes(bytes.fromhex("040000003412")) == original

    def test_one_variable_field_with_empty_payload(self) -> None:
        """An empty variable field exercises the start equals end span branch."""
        original = OneVar(a=Uint16List4(data=[]))
        # The offset still points to byte 4, and the payload is zero bytes long.
        encoded = original.encode_bytes()
        assert encoded == bytes.fromhex("04000000")
        assert OneVar.decode_bytes(encoded) == original


class TestMixedContainer:
    """Interleaved fixed and variable fields, the canonical wire layout."""

    def test_mixed_is_variable(self) -> None:
        """Any variable field forces the whole container to be variable-size."""
        assert Mixed.is_fixed_size() is False

    def test_mixed_get_byte_length_raises(self) -> None:
        """The mixed container has no fixed byte length and must raise."""
        with pytest.raises(SSZTypeError) as exc_info:
            Mixed.get_byte_length()
        assert exc_info.value.args[0] == "Mixed: variable-size container has no fixed byte length"

    def test_mixed_wire_layout(self) -> None:
        """The fixed slots and offsets land before the tail payloads in field order."""
        # Fixture state:
        #   a (Uint64) = 0xAABBCCDD       -> ddccbbaa00000000   (8 bytes)
        #   b offset   = 20               -> 14000000           (4 bytes)
        #   c (Uint32) = 0xEEFF           -> ffee0000           (4 bytes)
        #   d offset   = 24               -> 18000000           (4 bytes)
        #   b payload  = [1, 2] Uint16    -> 01000200           (4 bytes)
        #   d payload  = [3]   Uint16     -> 0300               (2 bytes)
        original = Mixed(
            a=Uint64(0xAABBCCDD),
            b=Uint16List4(data=[Uint16(1), Uint16(2)]),
            c=Uint32(0xEEFF),
            d=Uint16List4(data=[Uint16(3)]),
        )
        expected = bytes.fromhex("ddccbbaa0000000014000000ffee000018000000010002000300")
        assert original.encode_bytes() == expected
        assert Mixed.decode_bytes(expected) == original


class TestNestedContainer:
    """Containers nested as fields of other containers."""

    def test_fixed_inside_fixed_is_fixed(self) -> None:
        """A fixed container holding another fixed container stays fixed-size."""
        assert OuterFixedNested.is_fixed_size() is True
        # 8 bytes for z plus 16 bytes for the inner pair.
        assert OuterFixedNested.get_byte_length() == 24

    def test_fixed_inside_fixed_roundtrip(self) -> None:
        """Encoding lays out the outer field then the inner fields back to back."""
        original = OuterFixedNested(z=Uint64(7), inner=InnerFixed(x=Uint64(1), y=Uint64(2)))
        encoded = original.encode_bytes()
        assert encoded == bytes.fromhex("070000000000000001000000000000000200000000000000")
        assert OuterFixedNested.decode_bytes(encoded) == original

    def test_variable_inside_outer_is_variable(self) -> None:
        """A variable inner container forces the outer to be variable-size."""
        assert OuterVarNested.is_fixed_size() is False

    def test_variable_inside_outer_roundtrip(self) -> None:
        """The inner variable container is treated as a single variable field on the outer."""
        # Fixture state:
        #   head    = 99            -> 6300000000000000   (8 bytes fixed)
        #   inner offset = 12       -> 0c000000           (4 bytes)
        #   inner payload begins at byte 12:
        #     inner.a = 7           -> 0700000000000000   (8 bytes)
        #     inner.b offset = 12   -> 0c000000           (4 bytes)
        #     inner.b payload [1,2] -> 01000200           (4 bytes)
        original = OuterVarNested(
            head=Uint64(99),
            inner=InnerVar(a=Uint64(7), b=Uint16List4(data=[Uint16(1), Uint16(2)])),
        )
        expected = bytes.fromhex("63000000000000000c00000007000000000000000c00000001000200")
        assert original.encode_bytes() == expected
        assert OuterVarNested.decode_bytes(expected) == original


class TestSubclassInheritance:
    """Pydantic merges parent and child fields in declaration order."""

    def test_subclass_field_order_preserved(self) -> None:
        """The subclass exposes parent fields first then its own fields."""
        assert list(SignedAttestation.model_fields.keys()) == ["slot", "data", "signature"]

    def test_subclass_roundtrip(self) -> None:
        """A subclass that adds a fixed field after a variable field roundtrips correctly."""
        original = SignedAttestation(
            slot=Uint64(5),
            data=Uint16List4(data=[Uint16(1)]),
            signature=Uint64(99),
        )
        # Fixed part is slot (8) plus data offset (4) plus signature (8) for 20 bytes.
        # Data offset value is therefore 20 and the payload is [1] as Uint16.
        expected = bytes.fromhex("05000000000000001400000063000000000000000100")
        assert original.encode_bytes() == expected
        assert SignedAttestation.decode_bytes(expected) == original


class TestSerialize:
    """Stream-level behavior of the serialize method."""

    def test_serialize_returns_total_bytes_written(self) -> None:
        """Serialize returns the total byte count including the variable tail."""
        original = OneVar(a=Uint16List4(data=[Uint16(1), Uint16(2), Uint16(3)]))
        stream = io.BytesIO()
        # Fixed part is 4 bytes for the single offset.
        # The payload is 6 bytes for three Uint16 elements.
        assert original.serialize(stream) == 10
        assert stream.getvalue() == bytes.fromhex("04000000010002000300")


class TestDeserialize:
    """Stream-level behavior of the deserialize method."""

    def test_deserialize_with_scope_reads_full_value(self) -> None:
        """Reading from a stream with a matching scope reconstructs the value."""
        original = Mixed(
            a=Uint64(1),
            b=Uint16List4(data=[Uint16(7)]),
            c=Uint32(2),
            d=Uint16List4(data=[Uint16(8), Uint16(9)]),
        )
        encoded = original.encode_bytes()
        stream = io.BytesIO(encoded)
        assert Mixed.deserialize(stream, len(encoded)) == original


class TestErrors:
    """Spec-compliance error paths for malformed inputs."""

    @pytest.mark.parametrize(
        ("bad_offset", "expected_message"),
        [
            pytest.param(11, "Mixed: first offset 11 != fixed-part end 20", id="below_fixed_end"),
            pytest.param(21, "Mixed: first offset 21 != fixed-part end 20", id="above_fixed_end"),
        ],
    )
    def test_first_offset_must_match_fixed_part_end(
        self, bad_offset: int, expected_message: str
    ) -> None:
        """The first variable offset must equal the end of the fixed part."""
        # Fixed part of Mixed is 8 + 4 + 4 + 4 = 20 bytes.
        # The payload deviates by one byte in either direction from the canonical offset.
        data = (
            (1).to_bytes(8, "little")
            + bad_offset.to_bytes(4, "little")
            + (2).to_bytes(4, "little")
            + (24).to_bytes(4, "little")
            + bytes.fromhex("01000200")
            + bytes.fromhex("0300")
        )
        with pytest.raises(SSZSerializationError) as exc_info:
            Mixed.decode_bytes(data)
        assert exc_info.value.args[0] == expected_message

    def test_non_monotonic_offsets_raise(self) -> None:
        """A second offset below the first triggers a non-monotonic offsets error."""
        # Fixed part is 8 bytes for two Uint32 offsets.
        # First offset is 8 (valid), second offset is 5 (decreasing).
        data = (8).to_bytes(4, "little") + (5).to_bytes(4, "little") + b"\x34\x12"
        with pytest.raises(SSZSerializationError) as exc_info:
            TwoVar.decode_bytes(data)
        assert exc_info.value.args[0] == "TwoVar.a: non-monotonic offsets (8 > 5)"

    def test_short_input_on_fixed_field_raises(self) -> None:
        """A truncated stream on a fixed field surfaces the field type's own error."""
        # 15 bytes is one short of the 16-byte fixed width.
        with pytest.raises(SSZSerializationError) as exc_info:
            TwoUint64.decode_bytes(b"\x00" * 15)
        assert exc_info.value.args[0] == "Uint64: expected 8 bytes, got 7"

    def test_trailing_bytes_raises(self) -> None:
        """An input one byte longer than the canonical encoding is rejected."""
        with pytest.raises(SSZSerializationError) as exc_info:
            TwoUint64.decode_bytes(b"\x00" * 17)
        assert exc_info.value.args[0] == "TwoUint64: 1 trailing byte(s) after decode"


class TestFromHex:
    """Hex-string entry point for container decoding."""

    @pytest.mark.parametrize(
        "hex_input",
        [
            pytest.param("0xab", id="with_prefix"),
            pytest.param("ab", id="without_prefix"),
            pytest.param("0xAB", id="uppercase_with_prefix"),
        ],
    )
    def test_from_hex_accepts_prefix_and_case(self, hex_input: str) -> None:
        """Hex parsing tolerates the 0x prefix and mixed case alike."""
        assert OneByte.from_hex(hex_input) == OneByte(a=Uint8(0xAB))

    @pytest.mark.parametrize(
        "hex_input",
        [
            pytest.param("", id="empty"),
            pytest.param("0x", id="prefix_only"),
        ],
    )
    def test_from_hex_empty_string_decodes_empty_container(self, hex_input: str) -> None:
        """An empty hex string decodes to a zero-field container."""
        assert EmptyContainer.from_hex(hex_input) == EmptyContainer()

    def test_from_hex_bad_hex_raises_value_error(self) -> None:
        """Non-hex characters surface a ValueError from the underlying parser."""
        with pytest.raises(ValueError, match="non-hexadecimal number"):
            OneByte.from_hex("zz")
