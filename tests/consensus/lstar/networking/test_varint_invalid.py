"""Varint decoder invalid-input rejection vectors."""

import pytest

from consensus_testing import DecodeFailure, ExpectedRejection, NetworkingCodecTestFiller
from lean_spec.spec.forks import RejectionReason

pytestmark = pytest.mark.valid_until("Lstar")


def test_varint_truncated_mid_stream_rejected(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A varint whose final byte still has the continuation bit set is rejected.

    Given
    -----
    - two bytes 0x80 0x80.
    - both carry the continuation bit.
    - no further bytes complete the value.

    When
    ----
    - the bytes are decoded as a varint.

    Then
    ----
    - decoding is rejected because the varint is truncated.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="varint", raw_bytes="0x8080"),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_varint_longer_than_ten_bytes_rejected(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A varint running past ten bytes exceeds the 64-bit cap and is rejected.

    Given
    -----
    - eleven continuation bytes.
    - a 64-bit value fits in at most ten varint bytes.

    When
    ----
    - the bytes are decoded as a varint.

    Then
    ----
    - decoding is rejected because the varint is too long to represent.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="varint", raw_bytes="0x" + "80" * 11),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )
