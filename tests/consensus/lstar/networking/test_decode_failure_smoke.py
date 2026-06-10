"""Smoke vector for the decode-failure dispatch path of the networking codec fixture."""

import pytest

from consensus_testing import DecodeFailure, ExpectedRejection, NetworkingCodecTestFiller
from lean_spec.spec.forks import RejectionReason

pytestmark = pytest.mark.valid_until("Lstar")


def test_decode_failure_varint_truncated(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A truncated varint is rejected.

    Given
    -----
    - a single varint byte with the continuation bit set on its final byte.

    When
    ----
    - the bytes are decoded.

    Then
    ----
    - decoding is rejected because more bytes were expected.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="varint", raw_bytes="0x80"),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )
