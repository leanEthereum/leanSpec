"""SSZ decode-rejection vectors for malformed inputs."""

from typing import ClassVar

import pytest

from consensus_testing import ExpectedRejection, SSZTestFiller
from lean_spec.spec.forks import RejectionReason, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import Validator, Validators
from lean_spec.spec.ssz import BaseBitlist, BaseBitvector, Boolean, Bytes4, Bytes52, Uint32

pytestmark = pytest.mark.valid_until("Lstar")


class DecodeBitlist8(BaseBitlist):
    """Bitlist with an 8-bit limit, used to exercise bitlist-decode rejections."""

    LIMIT: ClassVar[int] = 8


class DecodeBitvector16(BaseBitvector):
    """Fixed-width 16-bit bitvector, used to exercise fixed-width length checks."""

    LENGTH: ClassVar[int] = 16


def test_bitlist_decode_rejects_empty_input(ssz_test: SSZTestFiller) -> None:
    """
    Decoding an empty input into a bitlist is rejected.

    Given
    -----
    - a bitlist type capped at eight bits.
    - an input of zero bytes.

    When
    ----
    - the input is decoded into that type.

    Then
    ----
    - decoding is rejected.
    - the reason is that no sentinel bit marks the bit-length.
    """
    ssz_test(
        type_name="DecodeBitlist8",
        value=DecodeBitlist8(data=[Boolean(False)]),
        raw_bytes="0x",
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_bitlist_decode_rejects_missing_delimiter(ssz_test: SSZTestFiller) -> None:
    """
    Decoding bitlist bytes that carry no set bit is rejected.

    Given
    -----
    - a bitlist type capped at eight bits.
    - the input byte 0x00, which holds eight clear bits and no sentinel.

    When
    ----
    - the input is decoded into that type.

    Then
    ----
    - decoding is rejected.
    - the reason is that no sentinel marks where the bitlist ends.
    """
    ssz_test(
        type_name="DecodeBitlist8",
        value=DecodeBitlist8(data=[Boolean(False)]),
        raw_bytes="0x00",
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_bitlist_decode_rejects_length_above_limit(ssz_test: SSZTestFiller) -> None:
    """
    Decoding a bitlist whose sentinel implies too many bits is rejected.

    Given
    -----
    - a bitlist type capped at eight bits.
    - the input bytes 0x0002, which place the sentinel at bit index nine.

    When
    ----
    - the input is decoded into that type.

    Then
    ----
    - decoding is rejected.
    - the reason is that the implied bit-length exceeds the limit.
    """
    ssz_test(
        type_name="DecodeBitlist8",
        value=DecodeBitlist8(data=[Boolean(False)]),
        raw_bytes="0x0002",
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_bitvector_decode_rejects_wrong_byte_length(ssz_test: SSZTestFiller) -> None:
    """
    Decoding a fixed-width bitvector from the wrong byte count is rejected.

    Given
    -----
    - a fixed-width bitvector that occupies exactly two bytes.
    - a single-byte input that underfills the vector.

    When
    ----
    - the input is decoded into that type.

    Then
    ----
    - decoding is rejected.
    - the reason is that the byte count does not match the fixed width.
    """
    ssz_test(
        type_name="DecodeBitvector16",
        value=DecodeBitvector16(data=[Boolean(False)] * 16),
        raw_bytes="0x00",
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_bytes4_decode_rejects_extra_trailing_bytes(ssz_test: SSZTestFiller) -> None:
    """
    Decoding a fixed-size byte array from a longer input is rejected.

    Given
    -----
    - a fixed-size four-byte array type.
    - a five-byte input with one extra trailing byte.

    When
    ----
    - the input is decoded into that type.

    Then
    ----
    - decoding is rejected.
    - the reason is that the extra trailing byte has no slot in the type.
    """
    ssz_test(
        type_name="Bytes4",
        value=Bytes4(b"\x00\x00\x00\x00"),
        raw_bytes="0x0102030405",
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_uint32_decode_rejects_wrong_byte_length(ssz_test: SSZTestFiller) -> None:
    """
    Decoding a four-byte uint from a shorter input is rejected.

    Given
    -----
    - a uint type that is always four bytes.
    - a three-byte input that underfills the value.

    When
    ----
    - the input is decoded into that type.

    Then
    ----
    - decoding is rejected.
    - the reason is that the byte length does not match the fixed size.
    """
    ssz_test(
        type_name="Uint32",
        value=Uint32(0),
        raw_bytes="0x010203",
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_validators_decode_rejects_index_mismatched_with_position(ssz_test: SSZTestFiller) -> None:
    """
    Decoding a registry whose stored index disagrees with its position is rejected.

    Given
    -----
    - a registry of two validators packed back to back.
    - the validator at position 0 stores index 0.
    - the validator at position 1 stores index 5.

    When
    ----
    - the input is decoded into the registry type.

    Then
    ----
    - decoding is rejected.
    - the reason is that the stored index must equal the list position.
    """
    ssz_test(
        type_name="Validators",
        value=Validators(
            data=[
                Validator(
                    attestation_public_key=Bytes52.zero(),
                    proposal_public_key=Bytes52.zero(),
                    index=ValidatorIndex(0),
                )
            ]
        ),
        raw_bytes=("0x" + "00" * 112 + "00" * 104 + "0500000000000000"),
        expected_rejection=ExpectedRejection(
            reason=RejectionReason.DECODE_ERROR,
            exact_message=(
                "validator at position 1 has index 5, "
                "but the registry index must equal the list position"
            ),
        ),
    )
