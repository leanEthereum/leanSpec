"""SSZ conformance test vectors for all non-container types."""

from typing import ClassVar

import pytest

from consensus_testing import SSZTestFiller
from lean_spec.node.networking.enr.eth2 import AttestationSubnets
from lean_spec.spec.crypto.koalabear import Fp, P
from lean_spec.spec.ssz import (
    BaseBitlist,
    BaseBitvector,
    Boolean,
    ByteList512KiB,
    Bytes4,
    Bytes32,
    Bytes52,
    Bytes64,
    SSZList,
    SSZVector,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
)

pytestmark = pytest.mark.valid_until("Lstar")


class SampleBitvector8(BaseBitvector):
    """8-bit bitvector. Fits exactly in one byte of SSZ encoding."""

    LENGTH: ClassVar[int] = 8


class SampleBitvector64(BaseBitvector):
    """64-bit bitvector. Spans multiple 32-byte Merkle chunks."""

    LENGTH: ClassVar[int] = 64


class SampleBitlist16(BaseBitlist):
    """Bitlist allowing up to 16 bits. Exercises the length-delimiting sentinel bit."""

    LIMIT: ClassVar[int] = 16


class SampleUint16Vector3(SSZVector[Uint16]):
    """Fixed-length vector of 3 two-byte elements (6 bytes total)."""

    LENGTH: ClassVar[int] = 3


class SampleUint64Vector4(SSZVector[Uint64]):
    """Fixed-length vector of 4 eight-byte elements (32 bytes, one full chunk)."""

    LENGTH: ClassVar[int] = 4


class SampleUint32List16(SSZList[Uint32]):
    """Variable-length list of up to 16 four-byte elements."""

    LIMIT: ClassVar[int] = 16
    ELEMENT_TYPE = Uint32


class SampleBytes32List8(SSZList[Bytes32]):
    """Variable-length list of up to 8 fixed-size 32-byte elements."""

    LIMIT: ClassVar[int] = 8
    ELEMENT_TYPE = Bytes32


def test_boolean_false(ssz_test: SSZTestFiller) -> None:
    """
    The boolean false round-trips through encoding unchanged.

    Given
    -----
    - the boolean value false.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the encoding is the byte 0x00.
    - the decoded value equals the original.
    """
    ssz_test(type_name="Boolean", value=Boolean(False))


def test_boolean_true(ssz_test: SSZTestFiller) -> None:
    """
    The boolean true round-trips through encoding unchanged.

    Given
    -----
    - the boolean value true.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the encoding is the byte 0x01.
    - the decoded value equals the original.
    """
    ssz_test(type_name="Boolean", value=Boolean(True))


def test_uint8_zero(ssz_test: SSZTestFiller) -> None:
    """
    A one-byte uint at its lower bound round-trips unchanged.

    Given
    -----
    - the value 0 as a one-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint8", value=Uint8(0))


def test_uint8_one(ssz_test: SSZTestFiller) -> None:
    """
    The smallest non-zero one-byte uint round-trips unchanged.

    Given
    -----
    - the value 1 as a one-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint8", value=Uint8(1))


def test_uint8_mid(ssz_test: SSZTestFiller) -> None:
    """
    A one-byte uint with its high bit set round-trips unchanged.

    Given
    -----
    - the value 128 as a one-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint8", value=Uint8(128))


def test_uint8_max(ssz_test: SSZTestFiller) -> None:
    """
    A one-byte uint at its upper bound round-trips unchanged.

    Given
    -----
    - the value 255 as a one-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint8", value=Uint8(2**8 - 1))


def test_uint16_zero(ssz_test: SSZTestFiller) -> None:
    """
    A two-byte uint at its lower bound round-trips unchanged.

    Given
    -----
    - the value 0 as a two-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint16", value=Uint16(0))


def test_uint16_one(ssz_test: SSZTestFiller) -> None:
    """
    The smallest non-zero two-byte uint round-trips unchanged.

    Given
    -----
    - the value 1 as a two-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint16", value=Uint16(1))


def test_uint16_mid(ssz_test: SSZTestFiller) -> None:
    """
    A two-byte uint with its high bit set round-trips unchanged.

    Given
    -----
    - the value 32768 as a two-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the little-endian byte order is preserved.
    """
    ssz_test(type_name="Uint16", value=Uint16(32768))


def test_uint16_max(ssz_test: SSZTestFiller) -> None:
    """
    A two-byte uint at its upper bound round-trips unchanged.

    Given
    -----
    - the value 65535 as a two-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint16", value=Uint16(2**16 - 1))


def test_uint32_zero(ssz_test: SSZTestFiller) -> None:
    """
    A four-byte uint at its lower bound round-trips unchanged.

    Given
    -----
    - the value 0 as a four-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint32", value=Uint32(0))


def test_uint32_one(ssz_test: SSZTestFiller) -> None:
    """
    The smallest non-zero four-byte uint round-trips unchanged.

    Given
    -----
    - the value 1 as a four-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint32", value=Uint32(1))


def test_uint32_mid(ssz_test: SSZTestFiller) -> None:
    """
    A four-byte uint with its high bit set round-trips unchanged.

    Given
    -----
    - the value 2147483648 as a four-byte uint (2^31).

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the four-byte little-endian layout is preserved.
    """
    ssz_test(type_name="Uint32", value=Uint32(2147483648))


def test_uint32_max(ssz_test: SSZTestFiller) -> None:
    """
    A four-byte uint at its upper bound round-trips unchanged.

    Given
    -----
    - the largest four-byte uint value (2^32 - 1).

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint32", value=Uint32(2**32 - 1))


def test_uint64_zero(ssz_test: SSZTestFiller) -> None:
    """
    An eight-byte uint at its lower bound round-trips unchanged.

    Given
    -----
    - the value 0 as an eight-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint64", value=Uint64(0))


def test_uint64_one(ssz_test: SSZTestFiller) -> None:
    """
    The smallest non-zero eight-byte uint round-trips unchanged.

    Given
    -----
    - the value 1 as an eight-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Uint64", value=Uint64(1))


def test_uint64_mid(ssz_test: SSZTestFiller) -> None:
    """
    An eight-byte uint with its high bit set round-trips unchanged.

    Given
    -----
    - the value 2^63 as an eight-byte uint.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the eight-byte little-endian layout is preserved.
    """
    ssz_test(type_name="Uint64", value=Uint64(2**63))


def test_uint64_max(ssz_test: SSZTestFiller) -> None:
    """
    An eight-byte uint at its upper bound round-trips unchanged.

    Given
    -----
    - the largest eight-byte uint value (2^64 - 1).

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the encoding is eight bytes of 0xff.
    """
    ssz_test(type_name="Uint64", value=Uint64(2**64 - 1))


def test_bytes4_zero(ssz_test: SSZTestFiller) -> None:
    """
    A four-byte array of zeros round-trips unchanged.

    Given
    -----
    - a four-byte array of all-zero bytes.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Bytes4", value=Bytes4(b"\x00" * 4))


def test_bytes4_typical(ssz_test: SSZTestFiller) -> None:
    """
    A four-byte array with non-zero content round-trips unchanged.

    Given
    -----
    - a four-byte array holding the bytes 0xdeadbeef.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Bytes4", value=Bytes4(b"\xde\xad\xbe\xef"))


def test_bytes32_zero(ssz_test: SSZTestFiller) -> None:
    """
    A 32-byte array of zeros round-trips unchanged.

    Given
    -----
    - a 32-byte array of all-zero bytes.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Bytes32", value=Bytes32.zero())


def test_bytes32_typical(ssz_test: SSZTestFiller) -> None:
    """
    A 32-byte array with uniform content round-trips unchanged.

    Given
    -----
    - a 32-byte array of the repeated byte 0xab.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Bytes32", value=Bytes32(b"\xab" * 32))


def test_bytes32_incremental(ssz_test: SSZTestFiller) -> None:
    """
    A 32-byte array with distinct bytes round-trips unchanged.

    Given
    -----
    - a 32-byte array holding the bytes 0x00 through 0x1f.
    - every byte distinct, so a byte swap would be detected.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Bytes32", value=Bytes32(bytes(range(32))))


def test_bytes52_zero(ssz_test: SSZTestFiller) -> None:
    """
    A 52-byte array of zeros round-trips unchanged.

    Given
    -----
    - a 52-byte array of all-zero bytes.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Bytes52", value=Bytes52.zero())


def test_bytes52_typical(ssz_test: SSZTestFiller) -> None:
    """
    A 52-byte array with uniform content round-trips unchanged.

    Given
    -----
    - a 52-byte array of the repeated byte 0xcd.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Bytes52", value=Bytes52(b"\xcd" * 52))


def test_bytes64_zero(ssz_test: SSZTestFiller) -> None:
    """
    A 64-byte array of zeros round-trips unchanged.

    Given
    -----
    - a 64-byte array of all-zero bytes.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Bytes64", value=Bytes64.zero())


def test_bytes64_typical(ssz_test: SSZTestFiller) -> None:
    """
    A 64-byte array with uniform content round-trips unchanged.

    Given
    -----
    - a 64-byte array of the repeated byte 0xef.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Bytes64", value=Bytes64(b"\xef" * 64))


def test_bytelist_empty(ssz_test: SSZTestFiller) -> None:
    """
    An empty byte list round-trips unchanged.

    Given
    -----
    - a byte list with no content.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="ByteList512KiB", value=ByteList512KiB(data=b""))


def test_bytelist_small(ssz_test: SSZTestFiller) -> None:
    """
    A small byte list round-trips unchanged.

    Given
    -----
    - a byte list holding four bytes.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="ByteList512KiB", value=ByteList512KiB(data=b"\x01\x02\x03\x04"))


def test_bytelist_medium(ssz_test: SSZTestFiller) -> None:
    """
    A medium byte list round-trips unchanged.

    Given
    -----
    - a byte list holding 256 bytes.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="ByteList512KiB", value=ByteList512KiB(data=bytes(range(256))))


def test_bitvector8_all_zero(ssz_test: SSZTestFiller) -> None:
    """
    An eight-bit vector with all bits clear round-trips unchanged.

    Given
    -----
    - an eight-bit vector whose bits are all clear.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the encoding is the byte 0x00.
    """
    ssz_test(
        type_name="SampleBitvector8",
        value=SampleBitvector8(data=[Boolean(False)] * 8),
    )


def test_bitvector8_all_one(ssz_test: SSZTestFiller) -> None:
    """
    An eight-bit vector with all bits set round-trips unchanged.

    Given
    -----
    - an eight-bit vector whose bits are all set.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the encoding is the byte 0xff.
    """
    ssz_test(
        type_name="SampleBitvector8",
        value=SampleBitvector8(data=[Boolean(True)] * 8),
    )


def test_bitvector8_mixed(ssz_test: SSZTestFiller) -> None:
    """
    An eight-bit vector with alternating bits round-trips unchanged.

    Given
    -----
    - an eight-bit vector with alternating set and clear bits.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the encoding is the byte 0x55.
    """
    ssz_test(
        type_name="SampleBitvector8",
        value=SampleBitvector8(
            data=[
                Boolean(True),
                Boolean(False),
                Boolean(True),
                Boolean(False),
                Boolean(True),
                Boolean(False),
                Boolean(True),
                Boolean(False),
            ]
        ),
    )


def test_bitvector64_all_zero(ssz_test: SSZTestFiller) -> None:
    """
    A 64-bit vector with all bits clear round-trips unchanged.

    Given
    -----
    - a 64-bit vector whose bits are all clear.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the encoding is eight zero bytes.
    """
    ssz_test(
        type_name="SampleBitvector64",
        value=SampleBitvector64(data=[Boolean(False)] * 64),
    )


def test_bitvector64_all_one(ssz_test: SSZTestFiller) -> None:
    """
    A 64-bit vector with all bits set round-trips unchanged.

    Given
    -----
    - a 64-bit vector whose bits are all set.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the encoding is eight bytes of 0xff.
    """
    ssz_test(
        type_name="SampleBitvector64",
        value=SampleBitvector64(data=[Boolean(True)] * 64),
    )


def test_bitvector64_mixed(ssz_test: SSZTestFiller) -> None:
    """
    A 64-bit vector with alternating bits round-trips unchanged.

    Given
    -----
    - a 64-bit vector with alternating set and clear bits.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - bit ordering is preserved across byte boundaries.
    """
    ssz_test(
        type_name="SampleBitvector64",
        value=SampleBitvector64(data=[Boolean(i % 2 == 0) for i in range(64)]),
    )


def test_bitlist_empty(ssz_test: SSZTestFiller) -> None:
    """
    An empty bitlist round-trips unchanged.

    Given
    -----
    - a bitlist with no bits.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the encoding is the sentinel-only byte 0x01.
    """
    ssz_test(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[]),
    )


def test_bitlist_single_true(ssz_test: SSZTestFiller) -> None:
    """
    A bitlist with one set bit round-trips unchanged.

    Given
    -----
    - a bitlist holding a single set bit.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the sentinel immediately follows the data bit.
    """
    ssz_test(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[Boolean(True)]),
    )


def test_bitlist_single_false(ssz_test: SSZTestFiller) -> None:
    """
    A bitlist with one clear bit round-trips unchanged.

    Given
    -----
    - a bitlist holding a single clear bit.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the sentinel is the only set bit in the byte.
    """
    ssz_test(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[Boolean(False)]),
    )


def test_bitlist_at_limit(ssz_test: SSZTestFiller) -> None:
    """
    A bitlist filled to its limit round-trips unchanged.

    Given
    -----
    - a bitlist filled to its 16-bit limit.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the sentinel lands in a new byte.
    """
    ssz_test(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[Boolean(True)] * 16),
    )


def test_bitlist_mixed(ssz_test: SSZTestFiller) -> None:
    """
    A partially filled bitlist round-trips unchanged.

    Given
    -----
    - a bitlist holding five mixed bits, below its 16-bit limit.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SampleBitlist16",
        value=SampleBitlist16(
            data=[
                Boolean(True),
                Boolean(False),
                Boolean(True),
                Boolean(True),
                Boolean(False),
            ]
        ),
    )


def test_uint16_vector3_zero(ssz_test: SSZTestFiller) -> None:
    """
    A three-element uint vector of zeros round-trips unchanged.

    Given
    -----
    - a vector of three two-byte uints, all zero.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SampleUint16Vector3",
        value=SampleUint16Vector3(data=[Uint16(0), Uint16(0), Uint16(0)]),
    )


def test_uint16_vector3_typical(ssz_test: SSZTestFiller) -> None:
    """
    A three-element uint vector with mixed values round-trips unchanged.

    Given
    -----
    - a vector of three two-byte uints with mixed values.
    - the last element at the maximum value (65535).

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SampleUint16Vector3",
        value=SampleUint16Vector3(data=[Uint16(100), Uint16(200), Uint16(65535)]),
    )


def test_uint64_vector4_zero(ssz_test: SSZTestFiller) -> None:
    """
    A four-element uint vector of zeros round-trips unchanged.

    Given
    -----
    - a vector of four eight-byte uints, all zero.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SampleUint64Vector4",
        value=SampleUint64Vector4(data=[Uint64(0), Uint64(0), Uint64(0), Uint64(0)]),
    )


def test_uint64_vector4_typical(ssz_test: SSZTestFiller) -> None:
    """
    A four-element uint vector spanning the value range round-trips unchanged.

    Given
    -----
    - a vector of four eight-byte uints spanning the full per-element range.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SampleUint64Vector4",
        value=SampleUint64Vector4(
            data=[
                Uint64(1),
                Uint64(2**32),
                Uint64(2**63),
                Uint64(2**64 - 1),
            ]
        ),
    )


def test_uint32_list_empty(ssz_test: SSZTestFiller) -> None:
    """
    An empty uint list round-trips unchanged.

    Given
    -----
    - a uint list with no elements.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SampleUint32List16",
        value=SampleUint32List16(data=[]),
    )


def test_uint32_list_single(ssz_test: SSZTestFiller) -> None:
    """
    A uint list with one element round-trips unchanged.

    Given
    -----
    - a uint list holding a single four-byte element.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SampleUint32List16",
        value=SampleUint32List16(data=[Uint32(42)]),
    )


def test_uint32_list_multiple(ssz_test: SSZTestFiller) -> None:
    """
    A uint list with three elements round-trips unchanged.

    Given
    -----
    - a uint list of three four-byte elements spanning the value range.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SampleUint32List16",
        value=SampleUint32List16(data=[Uint32(0), Uint32(100), Uint32(2**32 - 1)]),
    )


def test_bytes32_list_empty(ssz_test: SSZTestFiller) -> None:
    """
    An empty 32-byte-element list round-trips unchanged.

    Given
    -----
    - a list of 32-byte elements with no entries.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SampleBytes32List8",
        value=SampleBytes32List8(data=[]),
    )


def test_bytes32_list_single(ssz_test: SSZTestFiller) -> None:
    """
    A 32-byte-element list with one entry round-trips unchanged.

    Given
    -----
    - a list holding a single 32-byte element.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SampleBytes32List8",
        value=SampleBytes32List8(data=[Bytes32(b"\xaa" * 32)]),
    )


def test_bytes32_list_multiple(ssz_test: SSZTestFiller) -> None:
    """
    A 32-byte-element list with three entries round-trips unchanged.

    Given
    -----
    - a list holding three distinct 32-byte elements.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SampleBytes32List8",
        value=SampleBytes32List8(
            data=[
                Bytes32(b"\x01" * 32),
                Bytes32(b"\x02" * 32),
                Bytes32.zero(),
            ]
        ),
    )


def test_fp_zero(ssz_test: SSZTestFiller) -> None:
    """
    The zero field element round-trips unchanged.

    Given
    -----
    - the field element zero.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Fp", value=Fp(0))


def test_fp_one(ssz_test: SSZTestFiller) -> None:
    """
    The one field element round-trips unchanged.

    Given
    -----
    - the field element one.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Fp", value=Fp(1))


def test_fp_max(ssz_test: SSZTestFiller) -> None:
    """
    The largest valid field element round-trips unchanged.

    Given
    -----
    - the field element p minus one, the largest valid element.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Fp", value=Fp(P - 1))


def test_attestation_subnets_none(ssz_test: SSZTestFiller) -> None:
    """
    An attestation subnet bitfield with no subscriptions round-trips unchanged.

    Given
    -----
    - a subnet bitfield with all 64 bits clear.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="AttestationSubnets", value=AttestationSubnets.none())


def test_attestation_subnets_all(ssz_test: SSZTestFiller) -> None:
    """
    An attestation subnet bitfield with all subscriptions round-trips unchanged.

    Given
    -----
    - a subnet bitfield with all 64 bits set.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="AttestationSubnets", value=AttestationSubnets.all())


def test_attestation_subnets_partial(ssz_test: SSZTestFiller) -> None:
    """
    An attestation subnet bitfield with some subscriptions round-trips unchanged.

    Given
    -----
    - a subnet bitfield with five subnet identifiers set.
    - the set identifiers spanning the full 64-bit range.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="AttestationSubnets",
        value=AttestationSubnets.from_subnet_ids([0, 7, 15, 31, 63]),
    )
