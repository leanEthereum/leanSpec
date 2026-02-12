"""SSZ conformance tests for XMSS containers."""

import pytest
from consensus_testing import SSZTestFiller

from lean_spec.subspecs.containers.attestation import AggregationBits
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss import PublicKey, SecretKey, Signature
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.subtree import HashSubTree
from lean_spec.subspecs.xmss.types import (
    HASH_DIGEST_LENGTH,
    HashDigestList,
    HashDigestVector,
    HashTreeLayer,
    HashTreeLayers,
    HashTreeOpening,
    Parameter,
    PRFKey,
)
from lean_spec.types import Boolean, Uint64
from lean_spec.types.byte_arrays import ByteListMiB

pytestmark = pytest.mark.valid_until("Devnet")


# --- Helper functions ---


def _zero_hash_digest_vector() -> HashDigestVector:
    return HashDigestVector(data=[Fp(0) for _ in range(HASH_DIGEST_LENGTH)])


def _zero_parameter() -> Parameter:
    return Parameter(data=[Fp(0) for _ in range(Parameter.LENGTH)])


# --- PublicKey ---


def test_public_key_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for PublicKey with zero values."""
    ssz(
        type_name="PublicKey",
        value=PublicKey(root=_zero_hash_digest_vector(), parameter=_zero_parameter()),
    )


# --- Signature ---

# Empty path: path=[], rho=zeros, hashes=[]
SIGNATURE_EMPTY_PATH = bytes.fromhex(
    "24000000000000000000000000000000000000000000000000000000000000002800000004000000"
)

# With siblings: path=[zero, zero], rho=zeros, hashes=[zero]
SIGNATURE_WITH_SIBLINGS = bytes.fromhex(
    "24000000000000000000000000000000000000000000000000000000000000006800000004000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
)


def test_signature_empty_path(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Signature with empty authentication path."""
    ssz(type_name="Signature", value=Signature.decode_bytes(SIGNATURE_EMPTY_PATH))


def test_signature_with_siblings(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Signature with authentication path siblings."""
    ssz(type_name="Signature", value=Signature.decode_bytes(SIGNATURE_WITH_SIBLINGS))


# --- SecretKey ---


def test_secret_key_minimal(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for SecretKey with minimal values."""
    empty_subtree = HashSubTree(
        depth=Uint64(4),
        lowest_layer=Uint64(0),
        layers=HashTreeLayers(data=[]),
    )
    ssz(
        type_name="SecretKey",
        value=SecretKey(
            prf_key=PRFKey.zero(),
            parameter=_zero_parameter(),
            activation_epoch=Uint64(0),
            num_active_epochs=Uint64(1),
            top_tree=empty_subtree,
            left_bottom_tree_index=Uint64(0),
            left_bottom_tree=empty_subtree,
            right_bottom_tree=empty_subtree,
        ),
    )


# --- HashTreeOpening ---


def test_hash_tree_opening_empty(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashTreeOpening with no siblings."""
    ssz(
        type_name="HashTreeOpening",
        value=HashTreeOpening(siblings=HashDigestList(data=[])),
    )


def test_hash_tree_opening_single(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashTreeOpening with single sibling."""
    ssz(
        type_name="HashTreeOpening",
        value=HashTreeOpening(siblings=HashDigestList(data=[_zero_hash_digest_vector()])),
    )


def test_hash_tree_opening_multiple(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashTreeOpening with multiple siblings."""
    ssz(
        type_name="HashTreeOpening",
        value=HashTreeOpening(
            siblings=HashDigestList(
                data=[
                    _zero_hash_digest_vector(),
                    _zero_hash_digest_vector(),
                    _zero_hash_digest_vector(),
                ]
            )
        ),
    )


# --- HashTreeLayer ---


def test_hash_tree_layer_empty(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashTreeLayer with no nodes."""
    ssz(
        type_name="HashTreeLayer",
        value=HashTreeLayer(start_index=Uint64(0), nodes=HashDigestList(data=[])),
    )


def test_hash_tree_layer_single(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashTreeLayer with single node."""
    ssz(
        type_name="HashTreeLayer",
        value=HashTreeLayer(
            start_index=Uint64(0),
            nodes=HashDigestList(data=[_zero_hash_digest_vector()]),
        ),
    )


def test_hash_tree_layer_multiple(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashTreeLayer with multiple nodes."""
    ssz(
        type_name="HashTreeLayer",
        value=HashTreeLayer(
            start_index=Uint64(4),
            nodes=HashDigestList(data=[_zero_hash_digest_vector(), _zero_hash_digest_vector()]),
        ),
    )


# --- HashSubTree ---


def test_hash_subtree_empty(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashSubTree with no layers."""
    ssz(
        type_name="HashSubTree",
        value=HashSubTree(depth=Uint64(4), lowest_layer=Uint64(0), layers=HashTreeLayers(data=[])),
    )


def test_hash_subtree_with_layers(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for HashSubTree with layers."""
    ssz(
        type_name="HashSubTree",
        value=HashSubTree(
            depth=Uint64(4),
            lowest_layer=Uint64(0),
            layers=HashTreeLayers(
                data=[
                    HashTreeLayer(
                        start_index=Uint64(0),
                        nodes=HashDigestList(data=[_zero_hash_digest_vector()]),
                    )
                ]
            ),
        ),
    )


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
