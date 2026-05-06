"""Gossipsub RPC decoder: malformed-protobuf rejection vectors."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

from lean_spec.subspecs.networking.gossipsub.rpc import ProtobufDecodeError

pytestmark = pytest.mark.valid_until("Lstar")


def test_gossipsub_rpc_decode_rejects_unknown_wire_type(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """A protobuf tag with an unrecognised wire type must be rejected.

    The tag byte 0x0e encodes field number 1 with wire type 6. Wire types
    beyond the set 0, 1, 2, 5 are unassigned; any occurrence in RPC traffic
    must be rejected rather than silently skipped.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "gossipsub_rpc", "bytes": "0x0e"},
        expect_exception=ProtobufDecodeError,
    )


def test_gossipsub_rpc_decode_rejects_length_exceeding_data(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """A length-delimited field whose length runs past the payload is rejected.

    The payload starts with tag 0x0a (field 1, length-delimited wire type)
    followed by varint length 0x64 (100). The rest of the buffer carries
    zero bytes, so the declared length cannot possibly be covered. The
    decoder must raise before reading past the buffer end.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "gossipsub_rpc", "bytes": "0x0a64"},
        expect_exception=ProtobufDecodeError,
    )
