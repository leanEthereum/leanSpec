"""Snappy framing decoder malformed-input rejection vectors."""

import pytest

from consensus_testing import DecodeFailure, ExpectedRejection, NetworkingCodecTestFiller
from lean_spec.spec.forks import RejectionReason

pytestmark = pytest.mark.valid_until("Lstar")


def test_snappy_frame_decode_rejects_empty_input(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    Empty input is rejected as an invalid snappy frame.

    Given
    -----
    - zero input bytes.
    - every framed stream must begin with a ten-byte stream identifier.

    When
    ----
    - the bytes are decoded as a snappy frame.

    Then
    ----
    - decoding is rejected because the input is shorter than the identifier.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="snappy_frame", raw_bytes="0x"),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_snappy_frame_decode_rejects_wrong_stream_identifier(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A stream whose opening bytes are not the snappy magic is rejected.

    Given
    -----
    - ten zero bytes.
    - they satisfy the length check but carry the wrong magic.
    - a valid stream opens with ff 06 00 00 73 4e 61 50 70 59.

    When
    ----
    - the bytes are decoded as a snappy frame.

    Then
    ----
    - decoding is rejected at the stream-identifier check.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="snappy_frame", raw_bytes="0x" + "00" * 10),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_snappy_frame_decode_rejects_unknown_unskippable_chunk(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A chunk of an unassigned unskippable type is rejected.

    Given
    -----
    - a valid ten-byte stream identifier.
    - a following chunk with type byte 0x03 and a zero-length payload.
    - type 0x03 sits in the reserved-unskippable range.

    When
    ----
    - the bytes are decoded as a snappy frame.

    Then
    ----
    - decoding is rejected because the unskippable chunk type is unrecognised.
    """
    stream_identifier = "ff060000734e61507059"
    unknown_chunk = "03000000"
    networking_codec_test(
        codec=DecodeFailure(
            decoder="snappy_frame", raw_bytes="0x" + stream_identifier + unknown_chunk
        ),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )
