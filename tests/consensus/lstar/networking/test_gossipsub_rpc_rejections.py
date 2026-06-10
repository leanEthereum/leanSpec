"""Gossipsub RPC decoder malformed-protobuf rejection vectors."""

import pytest

from consensus_testing import DecodeFailure, ExpectedRejection, NetworkingCodecTestFiller
from lean_spec.spec.forks import RejectionReason

pytestmark = pytest.mark.valid_until("Lstar")


def test_gossipsub_rpc_decode_rejects_unknown_wire_type(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A protobuf tag with an unrecognised wire type is rejected.

    Given
    -----
    - a single tag byte 0x0e.
    - it encodes field number 1 with wire type 6.
    - wire types beyond 0, 1, 2, and 5 are unassigned.

    When
    ----
    - the bytes are decoded as a gossipsub RPC.

    Then
    ----
    - decoding is rejected because the wire type is unassigned.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="gossipsub_rpc", raw_bytes="0x0e"),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )


def test_gossipsub_rpc_decode_rejects_length_exceeding_data(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A length-delimited field whose length runs past the payload is rejected.

    Given
    -----
    - a tag byte 0x0a (field 1, length-delimited wire type).
    - a varint length 0x64 (100).
    - no payload bytes following the length.

    When
    ----
    - the bytes are decoded as a gossipsub RPC.

    Then
    ----
    - decoding is rejected because the declared length runs past the buffer end.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="gossipsub_rpc", raw_bytes="0x0a64"),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )
