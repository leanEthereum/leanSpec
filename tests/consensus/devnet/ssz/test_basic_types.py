"""SSZ conformance test vectors for all non-container types."""

from typing import ClassVar

import pytest
from consensus_testing import SSZTestFiller

from lean_spec.subspecs.koalabear import Fp, P
from lean_spec.subspecs.networking.enr.eth2 import AttestationSubnets, SyncCommitteeSubnets
from lean_spec.types import (
    BaseBitlist,
    BaseBitvector,
    Boolean,
    ByteListMiB,
    Bytes4,
    Bytes32,
    Bytes52,
    Bytes64,
    SSZList,
    SSZUnion,
    SSZVector,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
)

pytestmark = pytest.mark.valid_until("Lstar")


# --- Test helper types ---


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


class SampleUnionNone(SSZUnion):
    """Union whose selector 0 maps to None (the "absent value" arm)."""

    OPTIONS: ClassVar[tuple[type | None, ...]] = (None, Uint16, Uint32)


class SampleUnionTypes(SSZUnion):
    """Union with no None arm. Every selector maps to a concrete type."""

    OPTIONS: ClassVar[tuple[type | None, ...]] = (Uint8, Uint16)


# --- Boolean ---


def test_boolean_false(ssz: SSZTestFiller) -> None:
    """Boolean false encodes as 0x00."""
    ssz(type_name="Boolean", value=Boolean(False))


def test_boolean_true(ssz: SSZTestFiller) -> None:
    """Boolean true encodes as 0x01."""
    ssz(type_name="Boolean", value=Boolean(True))


# --- Uint8 ---


def test_uint8_zero(ssz: SSZTestFiller) -> None:
    """Uint8 lower bound (0)."""
    ssz(type_name="Uint8", value=Uint8(0))


def test_uint8_one(ssz: SSZTestFiller) -> None:
    """Uint8 smallest nonzero value (1)."""
    ssz(type_name="Uint8", value=Uint8(1))


def test_uint8_mid(ssz: SSZTestFiller) -> None:
    """Uint8 midpoint with high bit set (128)."""
    ssz(type_name="Uint8", value=Uint8(128))


def test_uint8_max(ssz: SSZTestFiller) -> None:
    """Uint8 upper bound (255)."""
    ssz(type_name="Uint8", value=Uint8(2**8 - 1))


# --- Uint16 ---


def test_uint16_zero(ssz: SSZTestFiller) -> None:
    """Uint16 lower bound (0)."""
    ssz(type_name="Uint16", value=Uint16(0))


def test_uint16_one(ssz: SSZTestFiller) -> None:
    """Uint16 smallest nonzero value (1)."""
    ssz(type_name="Uint16", value=Uint16(1))


def test_uint16_mid(ssz: SSZTestFiller) -> None:
    """Uint16 midpoint with high bit set (32768). Tests little-endian byte order."""
    ssz(type_name="Uint16", value=Uint16(32768))


def test_uint16_max(ssz: SSZTestFiller) -> None:
    """Uint16 upper bound (65535)."""
    ssz(type_name="Uint16", value=Uint16(2**16 - 1))


# --- Uint32 ---


def test_uint32_zero(ssz: SSZTestFiller) -> None:
    """Uint32 lower bound (0)."""
    ssz(type_name="Uint32", value=Uint32(0))


def test_uint32_one(ssz: SSZTestFiller) -> None:
    """Uint32 smallest nonzero value (1)."""
    ssz(type_name="Uint32", value=Uint32(1))


def test_uint32_mid(ssz: SSZTestFiller) -> None:
    """Uint32 midpoint with high bit set (2^31). Tests 4-byte little-endian layout."""
    ssz(type_name="Uint32", value=Uint32(2147483648))


def test_uint32_max(ssz: SSZTestFiller) -> None:
    """Uint32 upper bound (2^32 - 1)."""
    ssz(type_name="Uint32", value=Uint32(2**32 - 1))


# --- Uint64 ---


def test_uint64_zero(ssz: SSZTestFiller) -> None:
    """Uint64 lower bound (0)."""
    ssz(type_name="Uint64", value=Uint64(0))


def test_uint64_one(ssz: SSZTestFiller) -> None:
    """Uint64 smallest nonzero value (1)."""
    ssz(type_name="Uint64", value=Uint64(1))


def test_uint64_mid(ssz: SSZTestFiller) -> None:
    """Uint64 midpoint with high bit set (2^63). Tests 8-byte little-endian layout."""
    ssz(type_name="Uint64", value=Uint64(2**63))


def test_uint64_max(ssz: SSZTestFiller) -> None:
    """Uint64 upper bound (2^64 - 1). All bytes 0xFF."""
    ssz(type_name="Uint64", value=Uint64(2**64 - 1))


# --- Bytes4 ---


def test_bytes4_zero(ssz: SSZTestFiller) -> None:
    """Bytes4 all zeros. Minimal content, still pads to 32-byte chunk."""
    ssz(type_name="Bytes4", value=Bytes4(b"\x00" * 4))


def test_bytes4_typical(ssz: SSZTestFiller) -> None:
    """Bytes4 with nonzero content (0xDEADBEEF)."""
    ssz(type_name="Bytes4", value=Bytes4(b"\xde\xad\xbe\xef"))


# --- Bytes32 ---


def test_bytes32_zero(ssz: SSZTestFiller) -> None:
    """Bytes32 all zeros. One full chunk of zero bytes."""
    ssz(type_name="Bytes32", value=Bytes32.zero())


def test_bytes32_typical(ssz: SSZTestFiller) -> None:
    """Bytes32 with uniform nonzero content (0xAB repeated)."""
    ssz(type_name="Bytes32", value=Bytes32(b"\xab" * 32))


def test_bytes32_incremental(ssz: SSZTestFiller) -> None:
    """Bytes32 with every byte distinct (0x00..0x1F). Catches byte-swap errors."""
    ssz(type_name="Bytes32", value=Bytes32(bytes(range(32))))


# --- Bytes52 ---


def test_bytes52_zero(ssz: SSZTestFiller) -> None:
    """Bytes52 all zeros. Two chunks, second chunk partially zero-padded."""
    ssz(type_name="Bytes52", value=Bytes52.zero())


def test_bytes52_typical(ssz: SSZTestFiller) -> None:
    """Bytes52 with uniform nonzero content (0xCD repeated)."""
    ssz(type_name="Bytes52", value=Bytes52(b"\xcd" * 52))


# --- Bytes64 ---


def test_bytes64_zero(ssz: SSZTestFiller) -> None:
    """Bytes64 all zeros. Two full chunks of zero bytes."""
    ssz(type_name="Bytes64", value=Bytes64.zero())


def test_bytes64_typical(ssz: SSZTestFiller) -> None:
    """Bytes64 with uniform nonzero content (0xEF repeated)."""
    ssz(type_name="Bytes64", value=Bytes64(b"\xef" * 64))


# --- ByteListMiB ---


def test_bytelist_empty(ssz: SSZTestFiller) -> None:
    """Empty byte list. Zero-length content with length mix-in of zero."""
    ssz(type_name="ByteListMiB", value=ByteListMiB(data=b""))


def test_bytelist_small(ssz: SSZTestFiller) -> None:
    """Byte list with 4 bytes. Fits within a single 32-byte chunk."""
    ssz(type_name="ByteListMiB", value=ByteListMiB(data=b"\x01\x02\x03\x04"))


def test_bytelist_medium(ssz: SSZTestFiller) -> None:
    """Byte list with 256 bytes. Spans 8 full chunks."""
    ssz(type_name="ByteListMiB", value=ByteListMiB(data=bytes(range(256))))


# --- Bitvector ---


def test_bitvector8_all_zero(ssz: SSZTestFiller) -> None:
    """8-bit bitvector, all bits clear (0x00)."""
    ssz(
        type_name="SampleBitvector8",
        value=SampleBitvector8(data=[Boolean(False)] * 8),
    )


def test_bitvector8_all_one(ssz: SSZTestFiller) -> None:
    """8-bit bitvector, all bits set (0xFF)."""
    ssz(
        type_name="SampleBitvector8",
        value=SampleBitvector8(data=[Boolean(True)] * 8),
    )


def test_bitvector8_mixed(ssz: SSZTestFiller) -> None:
    """8-bit bitvector, alternating bits (0x55). Tests per-bit placement."""
    ssz(
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


def test_bitvector64_all_zero(ssz: SSZTestFiller) -> None:
    """64-bit bitvector, all bits clear. 8 zero bytes."""
    ssz(
        type_name="SampleBitvector64",
        value=SampleBitvector64(data=[Boolean(False)] * 64),
    )


def test_bitvector64_all_one(ssz: SSZTestFiller) -> None:
    """64-bit bitvector, all bits set. 8 bytes of 0xFF."""
    ssz(
        type_name="SampleBitvector64",
        value=SampleBitvector64(data=[Boolean(True)] * 64),
    )


def test_bitvector64_mixed(ssz: SSZTestFiller) -> None:
    """64-bit bitvector, alternating bits. Tests bit ordering across byte boundaries."""
    ssz(
        type_name="SampleBitvector64",
        value=SampleBitvector64(data=[Boolean(i % 2 == 0) for i in range(64)]),
    )


# --- Bitlist ---


def test_bitlist_empty(ssz: SSZTestFiller) -> None:
    """Empty bitlist. Sentinel-only encoding (0x01)."""
    ssz(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[]),
    )


def test_bitlist_single_true(ssz: SSZTestFiller) -> None:
    """Bitlist with one set bit. Sentinel immediately follows the data bit."""
    ssz(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[Boolean(True)]),
    )


def test_bitlist_single_false(ssz: SSZTestFiller) -> None:
    """Bitlist with one clear bit. The sentinel is the only set bit in the byte."""
    ssz(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[Boolean(False)]),
    )


def test_bitlist_at_limit(ssz: SSZTestFiller) -> None:
    """Bitlist filled to its 16-bit limit. Sentinel lands in a new byte."""
    ssz(
        type_name="SampleBitlist16",
        value=SampleBitlist16(data=[Boolean(True)] * 16),
    )


def test_bitlist_mixed(ssz: SSZTestFiller) -> None:
    """Bitlist with 5 mixed bits. Partial fill below the 16-bit limit."""
    ssz(
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


# --- SSZVector ---


def test_uint16_vector3_zero(ssz: SSZTestFiller) -> None:
    """3-element Uint16 vector, all zeros. 6 bytes total, padded to one chunk."""
    ssz(
        type_name="SampleUint16Vector3",
        value=SampleUint16Vector3(data=[Uint16(0), Uint16(0), Uint16(0)]),
    )


def test_uint16_vector3_typical(ssz: SSZTestFiller) -> None:
    """3-element Uint16 vector with mixed values, including the maximum (65535)."""
    ssz(
        type_name="SampleUint16Vector3",
        value=SampleUint16Vector3(data=[Uint16(100), Uint16(200), Uint16(65535)]),
    )


def test_uint64_vector4_zero(ssz: SSZTestFiller) -> None:
    """4-element Uint64 vector, all zeros. Fills exactly one 32-byte chunk."""
    ssz(
        type_name="SampleUint64Vector4",
        value=SampleUint64Vector4(data=[Uint64(0), Uint64(0), Uint64(0), Uint64(0)]),
    )


def test_uint64_vector4_typical(ssz: SSZTestFiller) -> None:
    """4-element Uint64 vector spanning the full value range per element."""
    ssz(
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


# --- SSZList ---


def test_uint32_list_empty(ssz: SSZTestFiller) -> None:
    """Empty Uint32 list. Length mix-in is zero, data tree is all-zero."""
    ssz(
        type_name="SampleUint32List16",
        value=SampleUint32List16(data=[]),
    )


def test_uint32_list_single(ssz: SSZTestFiller) -> None:
    """Uint32 list with one element. Minimal non-empty list."""
    ssz(
        type_name="SampleUint32List16",
        value=SampleUint32List16(data=[Uint32(42)]),
    )


def test_uint32_list_multiple(ssz: SSZTestFiller) -> None:
    """Uint32 list with three elements spanning the full value range."""
    ssz(
        type_name="SampleUint32List16",
        value=SampleUint32List16(data=[Uint32(0), Uint32(100), Uint32(2**32 - 1)]),
    )


def test_bytes32_list_empty(ssz: SSZTestFiller) -> None:
    """Empty Bytes32 list. Each element would occupy one full chunk."""
    ssz(
        type_name="SampleBytes32List8",
        value=SampleBytes32List8(data=[]),
    )


def test_bytes32_list_single(ssz: SSZTestFiller) -> None:
    """Bytes32 list with one element. Single chunk plus length mix-in."""
    ssz(
        type_name="SampleBytes32List8",
        value=SampleBytes32List8(data=[Bytes32(b"\xaa" * 32)]),
    )


def test_bytes32_list_multiple(ssz: SSZTestFiller) -> None:
    """Bytes32 list with three elements. Tests multi-chunk Merkle tree with mix-in."""
    ssz(
        type_name="SampleBytes32List8",
        value=SampleBytes32List8(
            data=[
                Bytes32(b"\x01" * 32),
                Bytes32(b"\x02" * 32),
                Bytes32.zero(),
            ]
        ),
    )


# --- SSZUnion ---


def test_union_none_arm(ssz: SSZTestFiller) -> None:
    """Union selecting the None arm (selector 0). Encodes as a single zero byte."""
    ssz(
        type_name="SampleUnionNone",
        value=SampleUnionNone(selector=0, value=None),
    )


def test_union_none_uint16_arm(ssz: SSZTestFiller) -> None:
    """Union selecting the Uint16 arm (selector 1) from a None-capable union."""
    ssz(
        type_name="SampleUnionNone",
        value=SampleUnionNone(selector=1, value=Uint16(1000)),
    )


def test_union_none_uint32_arm(ssz: SSZTestFiller) -> None:
    """Union selecting the Uint32 arm (selector 2) from a None-capable union."""
    ssz(
        type_name="SampleUnionNone",
        value=SampleUnionNone(selector=2, value=Uint32(70000)),
    )


def test_union_types_uint8_arm(ssz: SSZTestFiller) -> None:
    """Union selecting the Uint8 arm (selector 0) with maximum value."""
    ssz(
        type_name="SampleUnionTypes",
        value=SampleUnionTypes(selector=0, value=Uint8(255)),
    )


def test_union_types_uint16_arm(ssz: SSZTestFiller) -> None:
    """Union selecting the Uint16 arm (selector 1) with maximum value."""
    ssz(
        type_name="SampleUnionTypes",
        value=SampleUnionTypes(selector=1, value=Uint16(65535)),
    )


# --- Fp ---


def test_fp_zero(ssz: SSZTestFiller) -> None:
    """Field element zero. The additive identity."""
    ssz(type_name="Fp", value=Fp(0))


def test_fp_one(ssz: SSZTestFiller) -> None:
    """Field element one. The multiplicative identity."""
    ssz(type_name="Fp", value=Fp(1))


def test_fp_max(ssz: SSZTestFiller) -> None:
    """Field element p-1. The largest valid element in the field."""
    ssz(type_name="Fp", value=Fp(P - 1))


# --- Domain Bitvectors ---


def test_attestation_subnets_none(ssz: SSZTestFiller) -> None:
    """Attestation subnets with no subscriptions (all 64 bits clear)."""
    ssz(type_name="AttestationSubnets", value=AttestationSubnets.none())


def test_attestation_subnets_all(ssz: SSZTestFiller) -> None:
    """Attestation subnets with all 64 subscriptions active."""
    ssz(type_name="AttestationSubnets", value=AttestationSubnets.all())


def test_attestation_subnets_partial(ssz: SSZTestFiller) -> None:
    """Attestation subnets with 5 selected IDs spanning the full 64-bit range."""
    ssz(
        type_name="AttestationSubnets",
        value=AttestationSubnets.from_subnet_ids([0, 7, 15, 31, 63]),
    )


def test_sync_committee_subnets_none(ssz: SSZTestFiller) -> None:
    """Sync committee subnets with no subscriptions (all 4 bits clear)."""
    ssz(type_name="SyncCommitteeSubnets", value=SyncCommitteeSubnets.none())


def test_sync_committee_subnets_all(ssz: SSZTestFiller) -> None:
    """Sync committee subnets with all 4 subscriptions active."""
    ssz(type_name="SyncCommitteeSubnets", value=SyncCommitteeSubnets.all())


def test_sync_committee_subnets_partial(ssz: SSZTestFiller) -> None:
    """Sync committee subnets with 2 of 4 selected (boundary IDs 0 and 3)."""
    ssz(
        type_name="SyncCommitteeSubnets",
        value=SyncCommitteeSubnets.from_subnet_ids([0, 3]),
    )
