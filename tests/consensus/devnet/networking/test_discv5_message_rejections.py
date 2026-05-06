"""Discv5 message decoder: malformed-input rejection vectors."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

from lean_spec.subspecs.networking.discovery.codec import MessageDecodingError

pytestmark = pytest.mark.valid_until("Lstar")


def test_discv5_message_decode_rejects_empty_input(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Zero bytes is too short to carry a discv5 message type byte.

    Every discv5 message begins with a single type byte followed by an
    RLP-encoded payload. Empty input cannot satisfy even the type byte
    so the decoder must abort immediately.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "discv5_message", "bytes": "0x"},
        expect_exception=MessageDecodingError,
    )


def test_discv5_message_decode_rejects_unknown_type_byte(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """A type byte outside the assigned set is rejected.

    Only 0x01 through 0x06 are valid discv5 message types. A byte of 0xff
    followed by an empty RLP list carries no meaningful message and must
    be rejected rather than silently ignored.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "discv5_message", "bytes": "0xffc0"},
        expect_exception=MessageDecodingError,
    )


def test_discv5_ping_decode_rejects_wrong_element_count(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """A PING payload with the wrong number of RLP elements is rejected.

    PING requires exactly two fields: request_id and enr_seq. The payload
    0x01 (ping type) followed by 0xc0 (empty RLP list) carries zero
    elements, so the decoder must refuse to build a PING record.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "discv5_message", "bytes": "0x01c0"},
        expect_exception=MessageDecodingError,
    )
