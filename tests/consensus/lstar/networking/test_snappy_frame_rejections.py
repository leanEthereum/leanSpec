"""Snappy framing decoder: malformed-input rejection vectors."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

from lean_spec.snappy.decompress import SnappyDecompressionError

pytestmark = pytest.mark.valid_until("Lstar")


def test_snappy_frame_decode_rejects_empty_input(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Empty input is not a valid snappy frame and must be rejected.

    Every framed snappy stream begins with a ten-byte stream identifier.
    Zero bytes cannot satisfy that minimum so the decoder aborts early
    with SnappyDecompressionError.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "snappy_frame", "bytes": "0x"},
        expect_exception=SnappyDecompressionError,
    )


def test_snappy_frame_decode_rejects_wrong_stream_identifier(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """A stream whose opening bytes do not spell the snappy magic is rejected.

    A valid framed snappy stream starts with the ten-byte sequence
    `ff 06 00 00 73 4e 61 50 70 59` ("sNaPpY"). Ten zero bytes satisfy
    the length check but carry the wrong magic, so the decoder rejects
    the stream at the identifier check.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "snappy_frame", "bytes": "0x" + "00" * 10},
        expect_exception=SnappyDecompressionError,
    )


def test_snappy_frame_decode_rejects_unknown_unskippable_chunk(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """A chunk of an unassigned unskippable type is rejected.

    The byte sequence begins with a valid stream identifier followed by a
    chunk whose type byte is `0x03` with a zero-length payload. Type
    `0x03` sits in the reserved-unskippable range, so any unrecognised
    occurrence must force the decoder to abort.
    """
    stream_identifier = "ff060000734e61507059"
    unknown_chunk = "03000000"
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "snappy_frame", "bytes": "0x" + stream_identifier + unknown_chunk},
        expect_exception=SnappyDecompressionError,
    )
