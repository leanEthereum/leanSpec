"""Req/resp codec: wire-level rejection vectors.

Exercises the user-reachable CodecError paths in the req/resp decoder.
Each vector pins the exact exception class a client must raise when a
peer sends malformed framing.
"""

import pytest
from consensus_testing import NetworkingCodecTestFiller

from lean_spec.subspecs.networking.reqresp.codec import CodecError

pytestmark = pytest.mark.valid_until("Lstar")


def test_reqresp_decode_rejects_empty_request(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Decoding an empty request is rejected with CodecError.

    The req/resp framing demands a length-prefix varint followed by a
    compressed payload. Zero input carries neither, so the decoder must
    refuse before any downstream parsing.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "reqresp_request", "bytes": "0x"},
        expect_exception=CodecError,
    )


def test_reqresp_decode_rejects_invalid_varint_prefix(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """A request whose length prefix is a malformed varint is rejected with CodecError.

    Two continuation bytes with no terminator make the varint parse raise.
    The decoder wraps the underlying varint error in CodecError so clients
    can uniformly treat wire-level framing errors as a single class.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "reqresp_request", "bytes": "0x8080"},
        expect_exception=CodecError,
    )


def test_reqresp_decode_rejects_declared_length_above_max(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """A request whose declared length exceeds the ten-mebibyte cap is rejected.

    The varint 0x81 0x80 0x80 0x05 declares 10,485,761 bytes, one over the
    ten-mebibyte protocol cap. Refusing before decompression prevents a
    sender from forcing resource allocation proportional to a claimed size.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "reqresp_request", "bytes": "0x81808005"},
        expect_exception=CodecError,
    )
