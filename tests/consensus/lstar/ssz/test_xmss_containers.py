"""SSZ conformance tests for XMSS containers."""

import pytest
from consensus_testing import SSZTestFiller
from consensus_testing.keys import XmssKeyManager, create_dummy_signature

from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.xmss import PublicKey
from lean_spec.spec.crypto.xmss.aggregation import (
    TypeOneMultiSignature,
    TypeTwoMultiSignature,
)
from lean_spec.spec.crypto.xmss.constants import TARGET_CONFIG
from lean_spec.spec.crypto.xmss.merkle import HashTreeLayer
from lean_spec.spec.crypto.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
)
from lean_spec.spec.forks import AggregationBits, Slot, ValidatorIndex
from lean_spec.spec.ssz import Boolean, ByteList512KiB, Bytes32, Uint64

pytestmark = pytest.mark.valid_until("Lstar")


# --- Helper functions ---


def _zero_hash_digest_vector() -> HashDigestVector:
    """Build a hash digest vector with all field elements set to zero."""
    return HashDigestVector(data=[Fp(0) for _ in range(TARGET_CONFIG.HASH_LEN_FE)])


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
    sk = key_manager[ValidatorIndex(0)].attestation_keypair.secret_key
    signature = scheme.sign(sk, Slot(0), Bytes32(b"\x42" * 32))
    ssz(type_name="Signature", value=signature)


# --- TypeOneMultiSignature / TypeTwoMultiSignature ---


def _bits(participants: list[bool]) -> AggregationBits:
    """Build a participant bitfield from a list of booleans."""
    return AggregationBits(data=[Boolean(b) for b in participants])


def test_type_one_multi_signature_empty(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for a Type-1 proof with empty proof bytes."""
    ssz(
        type_name="TypeOneMultiSignature",
        value=TypeOneMultiSignature(
            participants=_bits([True]),
            proof=ByteList512KiB(data=b""),
        ),
    )


def test_type_one_multi_signature_with_proof(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for a Type-1 proof with non-empty proof bytes."""
    wire = b"\xde\xad\xbe\xef"
    ssz(
        type_name="TypeOneMultiSignature",
        value=TypeOneMultiSignature(
            participants=_bits([True, False, True]),
            proof=ByteList512KiB(data=wire),
        ),
    )


def test_type_two_multi_signature_roundtrip(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for a Type-2 proof envelope."""
    wire = b"\x01\x02\x03"
    ssz(
        type_name="TypeTwoMultiSignature",
        value=TypeTwoMultiSignature(proof=ByteList512KiB(data=wire)),
    )


# --- PublicKey ---


def test_public_key_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for PublicKey with ascending non-zero field elements."""
    ssz(
        type_name="PublicKey",
        value=PublicKey(
            root=HashDigestVector(data=[Fp(i + 1) for i in range(TARGET_CONFIG.HASH_LEN_FE)]),
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
                    HashDigestVector(
                        data=[Fp(i + j * 10) for i in range(TARGET_CONFIG.HASH_LEN_FE)]
                    )
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
                    HashDigestVector(data=[Fp(i + j * 7) for i in range(TARGET_CONFIG.HASH_LEN_FE)])
                    for j in range(2)
                ]
            ),
        ),
    )
