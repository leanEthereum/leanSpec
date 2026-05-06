"""SSZ: decode-failure vectors for malformed inputs.

Exercises the SSZ decoder's user-triggerable rejection paths through the
decode-failure fixture. Each vector captures the expected exception class
so client implementations can align on the rejection contract, not only
the roundtrip contract covered by the basic-types vectors.
"""

from typing import ClassVar

import pytest
from consensus_testing import SSZTestFiller

from lean_spec.types import (
    BaseBitlist,
    BaseBitvector,
    Boolean,
    Bytes4,
    Uint32,
)
from lean_spec.types.exceptions import SSZSerializationError, SSZValueError

pytestmark = pytest.mark.valid_until("Lstar")


class DecodeBitlist8(BaseBitlist):
    """Bitlist with an 8-bit limit, used to exercise bitlist-decode rejections."""

    LIMIT: ClassVar[int] = 8


class DecodeBitvector16(BaseBitvector):
    """Fixed-width 16-bit bitvector, used to exercise fixed-width length checks."""

    LENGTH: ClassVar[int] = 16


def test_bitlist_decode_rejects_empty_input(ssz: SSZTestFiller) -> None:
    """Bitlist decoding of zero bytes has no delimiter bit and must be rejected.

    Every SSZ bitlist encoding ends in a sentinel set bit that signals the
    bit-length. Empty input carries no such sentinel, so the decoder cannot
    determine how many bits the value was supposed to hold.
    """
    ssz(
        type_name="DecodeBitlist8",
        value=DecodeBitlist8(data=[Boolean(False)]),
        raw_bytes="0x",
        expect_exception=SSZSerializationError,
    )


def test_bitlist_decode_rejects_missing_delimiter(ssz: SSZTestFiller) -> None:
    """Bitlist bytes with no set bits carry no sentinel and must be rejected.

    A single 0x00 byte encodes eight clear bits with nothing marking the
    end of the logical bitlist. The decoder needs the sentinel to know
    where the payload stops.
    """
    ssz(
        type_name="DecodeBitlist8",
        value=DecodeBitlist8(data=[Boolean(False)]),
        raw_bytes="0x00",
        expect_exception=SSZSerializationError,
    )


def test_bitlist_decode_rejects_length_above_limit(ssz: SSZTestFiller) -> None:
    """Bitlist whose sentinel implies a bit-length beyond the type limit must be rejected.

    The payload 0x0002 places the sentinel at bit index nine, implying a
    nine-bit bitlist. The type caps at eight bits, so the decoder must
    refuse to widen past its own limit.
    """
    ssz(
        type_name="DecodeBitlist8",
        value=DecodeBitlist8(data=[Boolean(False)]),
        raw_bytes="0x0002",
        expect_exception=SSZValueError,
    )


def test_bitvector_decode_rejects_wrong_byte_length(ssz: SSZTestFiller) -> None:
    """Fixed-width bitvector decoding rejects inputs whose byte count does not match LENGTH.

    The fixed-width bitvector here occupies exactly two bytes. A single-byte
    input underfills the vector. The fixed-size decode path requires an
    exact byte match, so the decoder must reject.
    """
    ssz(
        type_name="DecodeBitvector16",
        value=DecodeBitvector16(data=[Boolean(False)] * 16),
        raw_bytes="0x00",
        expect_exception=SSZValueError,
    )


def test_bytes4_decode_rejects_extra_trailing_bytes(ssz: SSZTestFiller) -> None:
    """Fixed-size byte arrays reject inputs longer than their declared LENGTH.

    A four-byte fixed array cannot consume five input bytes. The extra
    trailing byte has no slot in the type, so the decoder must raise
    rather than silently ignore the overflow.
    """
    ssz(
        type_name="Bytes4",
        value=Bytes4(b"\x00\x00\x00\x00"),
        raw_bytes="0x0102030405",
        expect_exception=SSZValueError,
    )


def test_uint32_decode_rejects_wrong_byte_length(ssz: SSZTestFiller) -> None:
    """Fixed-size uint types reject input whose byte length does not match the type.

    A uint32 is always four bytes. A three-byte input underfills the slot
    and cannot be safely widened. The decoder raises rather than guessing
    a padding convention.
    """
    ssz(
        type_name="Uint32",
        value=Uint32(0),
        raw_bytes="0x010203",
        expect_exception=SSZSerializationError,
    )
