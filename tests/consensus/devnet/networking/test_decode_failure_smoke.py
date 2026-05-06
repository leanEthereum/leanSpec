"""Smoke test for the networking_codec fixture's decode_failure dispatcher.

Exercises the new `decode_failure` codec so the framework change is covered
independently of later negative-path content PRs.
"""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


def test_decode_failure_varint_truncated(networking_codec: NetworkingCodecTestFiller) -> None:
    """A truncated varint (continuation bit set on the final byte) must fail to decode.

    Pins the new `decode_failure` codec dispatch path on the
    networking_codec fixture.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "varint", "bytes": "0x80"},
        expect_exception=Exception,
    )
