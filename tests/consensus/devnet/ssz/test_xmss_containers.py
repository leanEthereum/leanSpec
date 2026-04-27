"""SSZ conformance tests for XMSS containers."""

import pytest
from consensus_testing import SSZTestFiller
from consensus_testing.keys import XmssKeyManager, create_dummy_signature

from lean_spec.forks.lstar.containers import ValidatorIndex
from lean_spec.forks.lstar.containers.attestation import AggregationBits
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss import PublicKey
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.types import (
    HASH_DIGEST_LENGTH,
    HashDigestList,
    HashDigestVector,
    HashTreeLayer,
    HashTreeOpening,
    Parameter,
)
from lean_spec.types import Boolean, ByteListMiB, Bytes32, Uint64

pytestmark = pytest.mark.valid_until("Lstar")


# --- Helper functions ---


def _zero_hash_digest_vector() -> HashDigestVector:
    """Build a hash digest vector with all field elements set to zero."""
    return HashDigestVector(data=[Fp(0) for _ in range(HASH_DIGEST_LENGTH)])


def _zero_parameter() -> Parameter:
    """Build a parameter vector with all field elements set to zero."""
    return Parameter(data=[Fp(0) for _ in range(Parameter.LENGTH)])


# --- PublicKey ---


def test_public_key_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for PublicKey with zero values."""
    ssz(
        type_name="PublicKey",
        value=PublicKey(root=_zero_hash_digest_vector(), parameter=_zero_parameter()),
    )


# --- Signature ---


def test_signature_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Signature with zero values."""
    ssz(type_name="Signature", value=create_dummy_signature())


def test_signature_actual(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for a real Signature produced by the XMSS signing algorithm."""
    key_manager = XmssKeyManager.shared()
    scheme = key_manager.scheme
    sk = key_manager[ValidatorIndex(0)].attestation_secret
    signature = scheme.sign(sk, Slot(0), Bytes32(b"\x42" * 32))
    ssz(type_name="Signature", value=signature)


# --- AggregatedSignatureProof ---


def test_aggregated_signature_proof_empty(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for AggregatedSignatureProof with empty proof data."""
    ssz(
        type_name="AggregatedSignatureProof",
        value=AggregatedSignatureProof(
            participants=AggregationBits(data=[Boolean(True)]),
            proof_data=ByteListMiB(data=b""),
        ),
    )


def test_aggregated_signature_proof_with_data(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for AggregatedSignatureProof with proof data."""
    ssz(
        type_name="AggregatedSignatureProof",
        value=AggregatedSignatureProof(
            participants=AggregationBits(data=[Boolean(True), Boolean(False), Boolean(True)]),
            proof_data=ByteListMiB(data=b"\xde\xad\xbe\xef"),
        ),
    )


def test_aggregated_signature_proof_multiple_participants(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for AggregatedSignatureProof with five of six participants active."""
    ssz(
        type_name="AggregatedSignatureProof",
        value=AggregatedSignatureProof(
            participants=AggregationBits(
                data=[
                    Boolean(True),
                    Boolean(True),
                    Boolean(True),
                    Boolean(False),
                    Boolean(True),
                    Boolean(True),
                ]
            ),
            proof_data=ByteListMiB(data=b"\x01\x02\x03\x04\x05\x06\x07\x08"),
        ),
    )


# --- PublicKey ---


def test_public_key_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for PublicKey with ascending non-zero field elements."""
    ssz(
        type_name="PublicKey",
        value=PublicKey(
            root=HashDigestVector(data=[Fp(i + 1) for i in range(HASH_DIGEST_LENGTH)]),
            parameter=Parameter(data=[Fp(100 + i) for i in range(Parameter.LENGTH)]),
        ),
    )


# --- HashTreeOpening ---


def test_hash_tree_opening_empty(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashTreeOpening with no sibling digests."""
    ssz(
        type_name="HashTreeOpening",
        value=HashTreeOpening(siblings=HashDigestList(data=[])),
    )


def test_hash_tree_opening_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashTreeOpening with three sibling digest vectors."""
    ssz(
        type_name="HashTreeOpening",
        value=HashTreeOpening(
            siblings=HashDigestList(
                data=[
                    HashDigestVector(data=[Fp(i + j * 10) for i in range(HASH_DIGEST_LENGTH)])
                    for j in range(3)
                ]
            )
        ),
    )


# --- HashTreeLayer ---


def test_hash_tree_layer_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashTreeLayer at index zero with no nodes."""
    ssz(
        type_name="HashTreeLayer",
        value=HashTreeLayer(
            start_index=Uint64(0),
            nodes=HashDigestList(data=[]),
        ),
    )


def test_hash_tree_layer_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashTreeLayer at index 42 with two node digest vectors."""
    ssz(
        type_name="HashTreeLayer",
        value=HashTreeLayer(
            start_index=Uint64(42),
            nodes=HashDigestList(
                data=[
                    HashDigestVector(data=[Fp(i + j * 7) for i in range(HASH_DIGEST_LENGTH)])
                    for j in range(2)
                ]
            ),
        ),
    )
