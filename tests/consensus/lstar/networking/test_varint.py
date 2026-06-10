"""LEB128 varint encoding roundtrip vectors."""

import pytest

from consensus_testing import NetworkingCodecTestFiller, VarintRoundtrip

pytestmark = pytest.mark.valid_until("Lstar")


def test_varint_zero(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The value zero roundtrips as a single byte.

    Given
    -----
    - the value 0.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the encoding is a single 0x00 byte.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=0),
    )


def test_varint_one(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The value one roundtrips as a single byte.

    Given
    -----
    - the value 1.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the encoding is a single 0x01 byte.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=1),
    )


def test_varint_max_one_byte(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The largest single-byte value roundtrips.

    Given
    -----
    - the value 127.
    - 127 is the largest value fitting in one byte.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=127),
    )


def test_varint_min_two_bytes(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The smallest two-byte value roundtrips.

    Given
    -----
    - the value 128.
    - 128 is the smallest value requiring two bytes.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=128),
    )


def test_varint_150(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The value 150 roundtrips.

    Given
    -----
    - the value 150.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=150),
    )


def test_varint_255(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The value 255 roundtrips.

    Given
    -----
    - the value 255.
    - 255 is the maximum 8-bit unsigned value.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=255),
    )


def test_varint_256(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The value 256 roundtrips.

    Given
    -----
    - the value 256.
    - 256 is the first value past the 8-bit range.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=256),
    )


def test_varint_300(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The value 300 roundtrips.

    Given
    -----
    - the value 300.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=300),
    )


def test_varint_max_two_bytes(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The largest two-byte value roundtrips.

    Given
    -----
    - the value 16383.
    - 16383 is the largest value fitting in two bytes.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=16383),
    )


def test_varint_min_three_bytes(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The smallest three-byte value roundtrips.

    Given
    -----
    - the value 16384.
    - 16384 is the smallest value requiring three bytes.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=16384),
    )


def test_varint_max_three_bytes(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The largest three-byte value roundtrips.

    Given
    -----
    - the value 2097151.
    - 2097151 is the largest value fitting in three bytes.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=2097151),
    )


def test_varint_max_four_bytes(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The largest four-byte value roundtrips.

    Given
    -----
    - the value 268435455.
    - 268435455 is the largest value fitting in four bytes.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=268435455),
    )


def test_varint_uint32_max(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The maximum 32-bit value roundtrips.

    Given
    -----
    - the value 2^32 - 1.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=2**32 - 1),
    )


def test_varint_uint64_max(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The maximum 64-bit value roundtrips.

    Given
    -----
    - the value 2^64 - 1.

    When
    ----
    - the value is encoded then decoded.

    Then
    ----
    - the decoded value equals the original.
    - the encoding requires ten bytes.
    """
    networking_codec_test(
        codec=VarintRoundtrip(value=2**64 - 1),
    )
