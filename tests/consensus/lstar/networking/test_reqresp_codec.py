"""Req/resp wire format encoding roundtrip vectors."""

import pytest

from consensus_testing import (
    NetworkingCodecTestFiller,
    ReqRespRequestRoundtrip,
    ReqRespResponseRoundtrip,
)

pytestmark = pytest.mark.valid_until("Lstar")


def test_request_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A request with an empty payload roundtrips.

    Given
    -----
    - an empty SSZ payload.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    - the varint length prefix is a single 0x00 byte.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x"),
    )


def test_request_small(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A request with a four-byte payload roundtrips.

    Given
    -----
    - a four-byte SSZ payload.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x01020304"),
    )


def test_request_varint_one_byte_max(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A request at the largest single-byte length prefix roundtrips.

    Given
    -----
    - a 127-byte SSZ payload.
    - 127 is the largest length encoded in one varint byte.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "ab" * 127),
    )


def test_request_varint_two_byte_min(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A request at the smallest two-byte length prefix roundtrips.

    Given
    -----
    - a 128-byte SSZ payload.
    - 128 is the smallest length requiring two varint bytes.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "cd" * 128),
    )


def test_request_compressible(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A request with highly repetitive data roundtrips.

    Given
    -----
    - a 1 KB payload of repeated four-byte groups.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    - the encoding exercises snappy copy tags.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "deadbeef" * 256),
    )


def test_request_sequential(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A request with low-compressibility data roundtrips.

    Given
    -----
    - a 256-byte payload of sequential byte values.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + bytes(range(256)).hex()),
    )


def test_request_all_zeros(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A request with uniform zero data roundtrips.

    Given
    -----
    - a 32-byte payload of zero bytes.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    - the checksum is computed over uniform input.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "00" * 32),
    )


def test_response_success_small(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A success response with a four-byte payload roundtrips.

    Given
    -----
    - response code 0 (success).
    - a four-byte SSZ payload.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded code and payload equal the originals.
    """
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data="0x01020304"),
    )


def test_response_success_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A success response with an empty payload roundtrips.

    Given
    -----
    - response code 0 (success).
    - an empty SSZ payload.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded code and payload equal the originals.
    """
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data="0x"),
    )


def test_response_invalid_request(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An invalid-request response carrying an error message roundtrips.

    Given
    -----
    - response code 1 (invalid request).
    - a UTF-8 error message payload.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded code and payload equal the originals.
    """
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=1, ssz_data="0x" + b"bad request".hex()),
    )


def test_response_server_error(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A server-error response carrying an error message roundtrips.

    Given
    -----
    - response code 2 (server error).
    - a UTF-8 error message payload.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded code and payload equal the originals.
    """
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=2, ssz_data="0x" + b"internal error".hex()),
    )


def test_response_resource_unavailable(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A resource-unavailable response carrying an error message roundtrips.

    Given
    -----
    - response code 3 (resource unavailable).
    - a UTF-8 error message payload.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded code and payload equal the originals.
    """
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=3, ssz_data="0x" + b"block not found".hex()),
    )


def test_response_success_sequential(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A success response with low-compressibility data roundtrips.

    Given
    -----
    - response code 0 (success).
    - a 256-byte payload of sequential byte values.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded code and payload equal the originals.
    """
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data="0x" + bytes(range(256)).hex()),
    )


def test_response_success_compressible(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A success response with highly repetitive data roundtrips.

    Given
    -----
    - response code 0 (success).
    - a 1 KB payload of repeated four-byte groups.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded code and payload equal the originals.
    """
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data="0x" + "cafebabe" * 256),
    )


def test_response_success_all_ff(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A success response with uniform high-byte data roundtrips.

    Given
    -----
    - response code 0 (success).
    - a 32-byte payload of 0xff bytes.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded code and payload equal the originals.
    """
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data="0x" + "ff" * 32),
    )


#
# Full stack: SSZ container → wire encode → wire decode → SSZ decode.
# These use the actual Lean consensus message types, not arbitrary bytes.

STATUS_SSZ = (
    "0x01010101010101010101010101010101010101010101010101010101010101016400"
    "000000000000020202020202020202020202020202020202020202020202020202020202"
    "02020296000000000000"
)
"""Status(finalized=Checkpoint(0x01..01, slot=100), head=Checkpoint(0x02..02, slot=150))."""

BLOCKS_BY_ROOT_SSZ = (
    "0x04000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)
"""BlocksByRootRequest with two roots (0xaa..aa, 0xbb..bb)."""

BLOCKS_BY_ROOT_EMPTY_SSZ = "0x04000000"
"""BlocksByRootRequest with empty root list (4-byte SSZ offset only)."""


def test_request_status(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A status request roundtrips through the full wire pipeline.

    Given
    -----
    - an SSZ-encoded status message.
    - the status request protocol.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data=STATUS_SSZ),
    )


def test_response_status(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A status success response roundtrips through the full wire pipeline.

    Given
    -----
    - response code 0 (success).
    - an SSZ-encoded status message.

    When
    ----
    - the response is encoded then decoded.

    Then
    ----
    - the decoded code and payload equal the originals.
    """
    networking_codec_test(
        codec=ReqRespResponseRoundtrip(response_code=0, ssz_data=STATUS_SSZ),
    )


def test_request_blocks_by_root(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A blocks-by-root request with two roots roundtrips.

    Given
    -----
    - an SSZ-encoded request listing two block roots.
    - the blocks-by-root request protocol.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data=BLOCKS_BY_ROOT_SSZ),
    )


def test_request_blocks_by_root_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A blocks-by-root request with no roots roundtrips.

    Given
    -----
    - an SSZ-encoded request with an empty root list.
    - the payload is a minimal four-byte SSZ offset.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data=BLOCKS_BY_ROOT_EMPTY_SSZ),
    )


def test_request_snappy_chunk_boundary(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A request exactly at the snappy chunk boundary roundtrips.

    Given
    -----
    - a 65536-byte payload.
    - 65536 is the snappy chunk size limit.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    - the encoding exercises multi-chunk framing.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "ab" * 65536),
    )


def test_request_multi_chunk(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A request spanning more than one snappy chunk roundtrips.

    Given
    -----
    - a 65537-byte payload.
    - 65537 is one byte past the chunk size limit.

    When
    ----
    - the request is encoded then decoded.

    Then
    ----
    - the decoded payload equals the original.
    """
    networking_codec_test(
        codec=ReqRespRequestRoundtrip(ssz_data="0x" + "cd" * 65537),
    )
