"""SSZ conformance tests for XMSS containers."""

import pytest

from consensus_testing import SSZTestFiller
from consensus_testing.keys import XmssKeyManager, create_dummy_signature
from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.xmss import PublicKey
from lean_spec.spec.crypto.xmss.constants import TARGET_CONFIG
from lean_spec.spec.crypto.xmss.merkle import HashTreeLayer
from lean_spec.spec.crypto.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
)
from lean_spec.spec.forks import AggregationBits, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    MultiMessageAggregate,
    SingleMessageAggregate,
)
from lean_spec.spec.ssz import Boolean, ByteList512KiB, Bytes32, Uint64

pytestmark = pytest.mark.valid_until("Lstar")


def _zero_hash_digest_vector() -> HashDigestVector:
    """Build a hash digest vector with all field elements set to zero."""
    return HashDigestVector(data=[Fp(0) for _ in range(TARGET_CONFIG.HASH_LENGTH_FIELD_ELEMENTS)])


def _zero_parameter() -> Parameter:
    """Build a parameter vector with all field elements set to zero."""
    return Parameter(data=[Fp(0) for _ in range(Parameter.LENGTH)])


def test_public_key_zero(ssz_test: SSZTestFiller) -> None:
    """
    A public key with zero values round-trips unchanged.

    Given
    -----
    - a public key whose root and parameter are all-zero field elements.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="PublicKey",
        value=PublicKey(root=_zero_hash_digest_vector(), parameter=_zero_parameter()),
    )


def test_signature_zero(ssz_test: SSZTestFiller) -> None:
    """
    A zero-filled signature round-trips unchanged.

    Given
    -----
    - a placeholder signature with all fields at zero.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Signature", value=create_dummy_signature())


def test_signature_actual(ssz_test: SSZTestFiller) -> None:
    """
    A real signature round-trips unchanged.

    Given
    -----
    - a signature produced by signing a message at slot zero.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    key_manager = XmssKeyManager.shared()
    scheme = key_manager.scheme
    secret_key = key_manager[ValidatorIndex(0)].attestation_keypair.secret_key
    signature = scheme.sign(secret_key, Slot(0), Bytes32(b"\x42" * 32))
    ssz_test(type_name="Signature", value=signature)


def _bits(participants: list[bool]) -> AggregationBits:
    """Build a participant bitfield from a list of booleans."""
    return AggregationBits(data=[Boolean(b) for b in participants])


def test_single_message_aggregate_empty(ssz_test: SSZTestFiller) -> None:
    """
    A single-message aggregate with empty proof bytes round-trips unchanged.

    Given
    -----
    - a single-message aggregate with one participant.
    - empty proof bytes.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SingleMessageAggregate",
        value=SingleMessageAggregate(
            participants=_bits([True]),
            proof=ByteList512KiB(data=b""),
        ),
    )


def test_single_message_aggregate_with_proof(ssz_test: SSZTestFiller) -> None:
    """
    A single-message aggregate with proof bytes round-trips unchanged.

    Given
    -----
    - a single-message aggregate with mixed participation bits.
    - four bytes of proof content.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    wire = b"\xde\xad\xbe\xef"
    ssz_test(
        type_name="SingleMessageAggregate",
        value=SingleMessageAggregate(
            participants=_bits([True, False, True]),
            proof=ByteList512KiB(data=wire),
        ),
    )


def test_multi_message_aggregate_roundtrip(ssz_test: SSZTestFiller) -> None:
    """
    A multi-message aggregate envelope round-trips unchanged.

    Given
    -----
    - a multi-message aggregate carrying three bytes of proof content.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    wire = b"\x01\x02\x03"
    ssz_test(
        type_name="MultiMessageAggregate",
        value=MultiMessageAggregate(proof=ByteList512KiB(data=wire)),
    )


def test_public_key_typical(ssz_test: SSZTestFiller) -> None:
    """
    A public key with non-zero field elements round-trips unchanged.

    Given
    -----
    - a public key whose root and parameter hold ascending non-zero values.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="PublicKey",
        value=PublicKey(
            root=HashDigestVector(
                data=[Fp(i + 1) for i in range(TARGET_CONFIG.HASH_LENGTH_FIELD_ELEMENTS)]
            ),
            parameter=Parameter(data=[Fp(100 + i) for i in range(Parameter.LENGTH)]),
        ),
    )


def test_hash_tree_opening_empty(ssz_test: SSZTestFiller) -> None:
    """
    A hash-tree opening with no siblings round-trips unchanged.

    Given
    -----
    - an opening whose sibling list is empty.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="HashTreeOpening",
        value=HashTreeOpening(siblings=HashDigestList(data=[])),
    )


def test_hash_tree_opening_typical(ssz_test: SSZTestFiller) -> None:
    """
    A hash-tree opening with three siblings round-trips unchanged.

    Given
    -----
    - an opening carrying three sibling digest vectors.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="HashTreeOpening",
        value=HashTreeOpening(
            siblings=HashDigestList(
                data=[
                    HashDigestVector(
                        data=[
                            Fp(i + j * 10) for i in range(TARGET_CONFIG.HASH_LENGTH_FIELD_ELEMENTS)
                        ]
                    )
                    for j in range(3)
                ]
            )
        ),
    )


def test_hash_tree_layer_zero(ssz_test: SSZTestFiller) -> None:
    """
    A hash-tree layer with no nodes round-trips unchanged.

    Given
    -----
    - a layer at start index zero with an empty node list.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="HashTreeLayer",
        value=HashTreeLayer(
            start_index=Uint64(0),
            nodes=HashDigestList(data=[]),
        ),
    )


def test_hash_tree_layer_typical(ssz_test: SSZTestFiller) -> None:
    """
    A hash-tree layer with two nodes round-trips unchanged.

    Given
    -----
    - a layer at start index 42 carrying two node digest vectors.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="HashTreeLayer",
        value=HashTreeLayer(
            start_index=Uint64(42),
            nodes=HashDigestList(
                data=[
                    HashDigestVector(
                        data=[
                            Fp(i + j * 7) for i in range(TARGET_CONFIG.HASH_LENGTH_FIELD_ELEMENTS)
                        ]
                    )
                    for j in range(2)
                ]
            ),
        ),
    )
