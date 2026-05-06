"""Varint decoder: invalid-input rejection vectors."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

from lean_spec.subspecs.networking.varint import VarintError

pytestmark = pytest.mark.valid_until("Lstar")


def test_varint_truncated_mid_stream_rejected(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """A varint whose final byte still has the continuation bit set is rejected.

    Two bytes (`0x80 0x80`) each carry the continuation bit but there are no
    further bytes to complete the value. The decoder must raise
    `VarintError("Truncated varint")`.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "varint", "bytes": "0x8080"},
        expect_exception=VarintError,
    )


def test_varint_longer_than_ten_bytes_rejected(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """A varint running eleven continuation bytes exceeds the 64-bit cap and is rejected.

    A uint64 fits in at most ten varint bytes (70 bits with 6 unused). Eleven
    continuation bytes means the decoder cannot represent the value and must
    raise `VarintError("Varint too long")`.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "varint", "bytes": "0x" + "80" * 11},
        expect_exception=VarintError,
    )
