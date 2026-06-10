"""Req/resp multi-chunk response stream vectors."""

import pytest

from consensus_testing import NetworkingCodecTestFiller, ReqRespResponseStream, ResponseChunkSpec

pytestmark = pytest.mark.valid_until("Lstar")


def test_stream_two_success_chunks(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A stream of two success chunks roundtrips to both records in order.

    Given
    -----
    - a first success chunk carrying distinct payload bytes.
    - a second success chunk carrying distinct payload bytes.

    When
    ----
    - the concatenated chunks are read back to back until the stream closes.

    Then
    ----
    - both records are produced in order.
    - a receiver that stops after the first chunk drops half the response.
    """
    networking_codec_test(
        codec=ReqRespResponseStream(
            chunks=[
                ResponseChunkSpec(response_code=0, ssz_data="0xdeadbeef"),
                ResponseChunkSpec(response_code=0, ssz_data="0xcafebabe"),
            ]
        ),
    )


def test_stream_success_then_resource_unavailable(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A success chunk followed by a resource-unavailable terminator roundtrips.

    Given
    -----
    - a success chunk carrying a payload.
    - a resource-unavailable chunk carrying an error message.
    - this mirrors a server ending early when it holds fewer items than asked.

    When
    ----
    - the concatenated chunks are read back to back until the stream closes.

    Then
    ----
    - the delivered payload record is produced.
    - the error terminator record is produced.
    """
    networking_codec_test(
        codec=ReqRespResponseStream(
            chunks=[
                ResponseChunkSpec(response_code=0, ssz_data="0x" + "11" * 16),
                ResponseChunkSpec(response_code=3, ssz_data="0x" + b"not found".hex()),
            ]
        ),
    )


def test_stream_three_success_chunks_with_compressible_payloads(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    Three success chunks with compressible payloads roundtrip in order.

    Given
    -----
    - three success chunks whose payloads compress well.
    - each chunk carries its own snappy stream-identifier preamble.

    When
    ----
    - the concatenated chunks are read back to back until the stream closes.

    Then
    ----
    - all three records are produced in order.
    - a parser that resets snappy state between chunks matches a stateful parser.
    """
    networking_codec_test(
        codec=ReqRespResponseStream(
            chunks=[
                ResponseChunkSpec(response_code=0, ssz_data="0x" + "00" * 64),
                ResponseChunkSpec(response_code=0, ssz_data="0x" + "ff" * 64),
                ResponseChunkSpec(response_code=0, ssz_data="0x" + "aa" * 64),
            ]
        ),
    )
