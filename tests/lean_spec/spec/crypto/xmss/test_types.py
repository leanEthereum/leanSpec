"""Tests for the base SSZ types of the XMSS signature scheme."""

import pytest

from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.xmss.constants import TEST_CONFIG
from lean_spec.spec.crypto.xmss.field import random_domain
from lean_spec.spec.crypto.xmss.types import (
    NODE_LIST_LIMIT,
    ChainTweak,
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
    Randomness,
    TreeTweak,
)
from lean_spec.spec.ssz import Uint64
from lean_spec.spec.ssz.exceptions import SSZValueError


def test_tree_tweak_fields() -> None:
    """A tree tweak stores its level and node index in order."""
    assert TreeTweak(level=3, index=Uint64(7)) == (3, Uint64(7))


def test_chain_tweak_fields() -> None:
    """A chain tweak stores its epoch, chain index, and step in order."""
    assert ChainTweak(epoch=Uint64(2), chain_index=5, step=1) == (Uint64(2), 5, 1)


def test_node_list_limit_is_twice_the_leaf_row() -> None:
    """The sparse-layer cap is twice the widest bottom-tree leaf row."""
    assert NODE_LIST_LIMIT == 2 * TEST_CONFIG.LEAVES_PER_BOTTOM_TREE


def test_hash_digest_vector_length_is_digest_length() -> None:
    """A digest vector holds exactly one Poseidon output worth of elements."""
    assert HashDigestVector.LENGTH == TEST_CONFIG.HASH_LENGTH_FIELD_ELEMENTS


def test_hash_digest_vector_accepts_exact_length() -> None:
    """A digest vector of the configured length validates."""
    data = [Fp(value=i) for i in range(TEST_CONFIG.HASH_LENGTH_FIELD_ELEMENTS)]
    assert HashDigestVector(data=data).data == tuple(data)


def test_hash_digest_vector_rejects_wrong_length() -> None:
    """A digest vector of the wrong length fails validation."""
    with pytest.raises(SSZValueError):
        HashDigestVector(data=[Fp(value=0)] * (TEST_CONFIG.HASH_LENGTH_FIELD_ELEMENTS + 1))


def test_parameter_length_is_parameter_length() -> None:
    """A parameter holds the configured number of personalization elements."""
    assert Parameter.LENGTH == TEST_CONFIG.PARAMETER_LENGTH


def test_randomness_length_is_randomness_length() -> None:
    """The signing randomness holds the configured number of elements."""
    assert Randomness.LENGTH == TEST_CONFIG.RAND_LENGTH_FIELD_ELEMENTS


def test_hash_digest_list_limit_is_node_list_limit() -> None:
    """The digest list cap matches the sparse-layer node limit."""
    assert HashDigestList.LIMIT == NODE_LIST_LIMIT


def test_hash_digest_list_accepts_limit_entries() -> None:
    """A digest list filled to the cap validates."""
    nodes = [random_domain(TEST_CONFIG) for _ in range(NODE_LIST_LIMIT)]
    assert len(HashDigestList(data=nodes).data) == NODE_LIST_LIMIT


def test_hash_digest_list_rejects_over_limit() -> None:
    """A digest list one entry past the cap fails validation."""
    nodes = [random_domain(TEST_CONFIG) for _ in range(NODE_LIST_LIMIT + 1)]
    with pytest.raises(SSZValueError):
        HashDigestList(data=nodes)


def test_hash_tree_opening_roundtrips_through_ssz() -> None:
    """An opening encodes and decodes back to an equal value."""
    siblings = [random_domain(TEST_CONFIG) for _ in range(3)]
    opening = HashTreeOpening(siblings=HashDigestList(data=siblings))
    assert HashTreeOpening.decode_bytes(opening.encode_bytes()) == opening


def test_hash_tree_opening_empty_is_allowed() -> None:
    """An opening with no siblings is a valid empty path."""
    opening = HashTreeOpening(siblings=HashDigestList(data=[]))
    assert len(opening.siblings) == 0
