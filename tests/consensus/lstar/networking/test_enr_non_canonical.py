"""ENR decoder: non-canonical key-order rejection vector.

EIP-778 requires ENR key/value pairs to be lexicographically ordered
in the signed RLP list. A decoder that accepts unordered keys would
verify records whose canonical form differs from the bytes on the
wire, breaking the signature covenant.
"""

import pytest
from consensus_testing import NetworkingCodecTestFiller

from lean_spec.types.rlp import encode_rlp

pytestmark = pytest.mark.valid_until("Lstar")


def _build_unsorted_enr_rlp() -> bytes:
    """Build an RLP-encoded ENR whose key/value pairs are not sorted.

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
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """An ENR with keys outside lexicographic order must be rejected.

    Pins EIP-778's canonical-ordering requirement. A client that decodes
    such a record would verify a signature over bytes the signer never
    produced.
    """
    networking_codec(
        codec_name="decode_failure",
        input={"decoder": "enr", "bytes": UNSORTED_ENR_HEX},
        expect_exception=ValueError,
    )
