"""SSZ conformance tests for XMSS containers."""

import pytest
from consensus_testing import SSZTestFiller
from consensus_testing.keys import create_dummy_signature, get_shared_key_manager

from lean_spec.subspecs.containers import ValidatorIndex
from lean_spec.subspecs.containers.attestation import AggregationBits
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss import PublicKey
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.types import (
    HASH_DIGEST_LENGTH,
    HashDigestVector,
    Parameter,
)
from lean_spec.types import Boolean, ByteListMiB, Bytes32

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


def test_signature_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Signature with zero values."""
    ssz(type_name="Signature", value=create_dummy_signature())


def test_signature_actual(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for a cryptographically valid Signature produced by signing."""
    key_manager = get_shared_key_manager()
    scheme = key_manager.scheme
    _, sk = key_manager.keys[ValidatorIndex(0)]
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
