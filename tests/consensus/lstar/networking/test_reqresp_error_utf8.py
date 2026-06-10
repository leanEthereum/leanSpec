"""Req/resp error-response payload roundtrip at size and UTF-8 boundaries."""

import pytest

from consensus_testing import NetworkingCodecTestFiller, ReqRespResponseRoundtrip

pytestmark = pytest.mark.valid_until("Lstar")


def test_reqresp_error_at_max_error_message_size(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    An error response at the maximum error-message size roundtrips.

    Given
    -----
    - response code 1 (invalid request).
    - a 256-byte payload.
    - 256 bytes is the limit error strings are truncated to.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original byte-for-byte.
    """
    payload = b"e" * 256
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=1, ssz_data="0x" + payload.hex()),
    )


def test_reqresp_error_with_multi_byte_utf8(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    An error response carrying multi-byte UTF-8 text roundtrips byte-for-byte.

    Given
    -----
    - response code 2 (server error).
    - a payload of multi-byte UTF-8 text that is not ASCII-only.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original byte-for-byte.
    """
    payload = "errür😀fail".encode()
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=2, ssz_data="0x" + payload.hex()),
    )


def test_reqresp_error_resource_unavailable_with_informational_text(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A resource-unavailable response carrying a short message roundtrips.

    Given
    -----
    - response code 3 (resource unavailable).
    - a short descriptive message payload.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded code and payload equal the originals.
    """
    payload = b"block not found"
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=3, ssz_data="0x" + payload.hex()),
    )
