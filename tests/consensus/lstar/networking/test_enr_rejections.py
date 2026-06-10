"""ENR RLP decoder: malformed-input rejection vectors."""

import pytest

from consensus_testing import DecodeFailure, ExpectedRejection, NetworkingCodecTestFiller
from lean_spec.spec.forks import RejectionReason

pytestmark = pytest.mark.valid_until("Lstar")


def test_enr_decode_rejects_oversize_payload(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    An ENR payload above the 300-byte cap is rejected.

    Given
    -----
    - a 301-byte input, one byte over the 300-byte ENR size cap.

    When
    ----
    - the bytes are decoded.

    Then
    ----
    - decoding is rejected because the payload exceeds the size cap.
    """
    oversize = "0x" + "ff" * 301
    networking_codec_test(
        codec=DecodeFailure(decoder="enr", raw_bytes=oversize),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_enr_decode_rejects_malformed_rlp(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    An input that is not an RLP list is rejected.

    Given
    -----
    - the single byte 0x00.
    - this is valid RLP for the value 0x00, but not for a list.

    When
    ----
    - the bytes are decoded.

    Then
    ----
    - decoding is rejected because a list header was required.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="enr", raw_bytes="0x00"),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )
