"""Req/resp multi-chunk response stream vectors.

Pins the concatenated byte layout of a libp2p request/response stream
carrying multiple chunks. Each chunk is its own [code][varint][snappy]
triple; clients must read them back-to-back until the stream closes
and produce the same ordered list of (code, sszData) records.
"""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


def test_stream_two_success_chunks(networking_codec: NetworkingCodecTestFiller) -> None:
    """Stream with two SUCCESS chunks carrying distinct payload bytes.

    Pins the concatenation of two independent response frames. Clients
    must read both records before signalling EOF, so a receiver that
    stops after the first chunk drops half the response.
    """
    networking_codec(
        codec_name="reqresp_response_stream",
        input={
            "chunks": [
                {"responseCode": 0, "sszData": "0xdeadbeef"},
                {"responseCode": 0, "sszData": "0xcafebabe"},
            ],
        },
    )


def test_stream_success_then_resource_unavailable(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """A SUCCESS chunk followed by a RESOURCE_UNAVAILABLE terminator.

    Real servers end a multi-chunk response early when the peer asked
    for more items than the server holds. The vector pins the exact
    concatenation so clients surface both the delivered payload and
    the error terminator.
    """
    networking_codec(
        codec_name="reqresp_response_stream",
        input={
            "chunks": [
                {"responseCode": 0, "sszData": "0x" + "11" * 16},
                {"responseCode": 3, "sszData": "0x" + b"not found".hex()},
            ],
        },
    )


def test_stream_three_success_chunks_with_compressible_payloads(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Three SUCCESS chunks whose payloads compress well.

    Exercises the N>2 case and highlights that each chunk carries its
    own snappy stream-identifier preamble inside the concatenated bytes;
    stream-level parsers that reset snappy state between chunks must
    produce identical output to stateful parsers.
    """
    networking_codec(
        codec_name="reqresp_response_stream",
        input={
            "chunks": [
                {"responseCode": 0, "sszData": "0x" + "00" * 64},
                {"responseCode": 0, "sszData": "0x" + "ff" * 64},
                {"responseCode": 0, "sszData": "0x" + "aa" * 64},
            ],
        },
    )
