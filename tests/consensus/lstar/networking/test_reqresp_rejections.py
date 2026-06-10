"""Req/resp codec wire-level rejection vectors."""

import pytest

from consensus_testing import DecodeFailure, ExpectedRejection, NetworkingCodecTestFiller
from lean_spec.spec.forks import RejectionReason

pytestmark = pytest.mark.valid_until("Lstar")


def test_reqresp_decode_rejects_empty_request(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    Decoding an empty request is rejected.

    Given
    -----
    - zero input bytes.
    - the framing requires a length-prefix varint followed by a payload.

    When
    ----
    - the bytes are decoded as a request.

    Then
    ----
    - decoding is rejected because neither field is present.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="reqresp_request", raw_bytes="0x"),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_reqresp_decode_rejects_invalid_varint_prefix(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A request whose length prefix is a malformed varint is rejected.

    Given
    -----
    - two bytes 0x80 0x80.
    - both carry the continuation bit with no terminator.

    When
    ----
    - the bytes are decoded as a request.

    Then
    ----
    - decoding is rejected because the length prefix is an incomplete varint.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="reqresp_request", raw_bytes="0x8080"),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_reqresp_decode_rejects_declared_length_above_max(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A request whose declared length exceeds the cap is rejected.

    Given
    -----
    - a length prefix declaring 10,485,761 bytes.
    - that is one byte over the ten-mebibyte protocol cap.

    When
    ----
    - the bytes are decoded as a request.

    Then
    ----
    - decoding is rejected before decompression because the length is over the cap.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="reqresp_request", raw_bytes="0x81808005"),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )
