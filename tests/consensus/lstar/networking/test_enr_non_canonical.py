"""Rejection vector for an ENR whose RLP keys are not in canonical order."""

import pytest

from consensus_testing import DecodeFailure, ExpectedRejection, NetworkingCodecTestFiller
from lean_spec.node.networking.enr.rlp import encode_rlp
from lean_spec.spec.forks import RejectionReason

pytestmark = pytest.mark.valid_until("Lstar")


def _build_unsorted_enr_rlp() -> bytes:
    """
    Build an RLP-encoded ENR whose key/value pairs are not sorted.

    EIP-778 mandates lexicographic key ordering. The decoder must reject
    any ENR whose on-the-wire RLP list has keys out of order.
    """
    # Placeholder 64-byte signature. Its contents do not matter because
    # the decoder rejects before even looking at the signature: the
    # key-ordering check runs during RLP-list traversal.
    signature = b"\x00" * 64
    seq = b"\x01"
    # "ip" > "id" lexicographically, so placing "ip" before "id" violates
    # the EIP-778 canonical ordering.
    ip_key = b"ip"
    ip_value = b"\x7f\x00\x00\x01"
    id_key = b"id"
    id_value = b"v4"
    return encode_rlp([signature, seq, ip_key, ip_value, id_key, id_value])


UNSORTED_ENR_HEX: str = "0x" + _build_unsorted_enr_rlp().hex()


def test_enr_decode_rejects_non_canonical_key_order(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    An ENR with keys outside lexicographic order is rejected.

    Given
    -----
    - an RLP-encoded ENR whose key/value pairs are not lexicographically sorted.
    - the "ip" key precedes the "id" key, violating canonical order.

    When
    ----
    - the bytes are decoded.

    Then
    ----
    - decoding is rejected because the key order is non-canonical.
    """
    networking_codec_test(
        codec=DecodeFailure(decoder="enr", raw_bytes=UNSORTED_ENR_HEX),
        expected_rejection=ExpectedRejection(reason=RejectionReason.DECODE_ERROR),
    )
