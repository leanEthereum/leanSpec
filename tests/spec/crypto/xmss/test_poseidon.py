"""Tests for the Poseidon hash engine wrapper used by the XMSS scheme."""

import pytest

from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.xmss.constants import TEST_CONFIG
from lean_spec.spec.crypto.xmss.field import random_domain
from lean_spec.spec.crypto.xmss.poseidon import POSEIDON
from lean_spec.spec.crypto.xmss.types import (
    ChainTweak,
    HashDigestVector,
    Parameter,
    TreeTweak,
)
from lean_spec.spec.ssz import Uint64


def _parameter() -> Parameter:
    """Return a fixed public parameter for hashing tests."""
    return Parameter(data=[Fp(value=1)] * TEST_CONFIG.PARAMETER_LENGTH)


@pytest.mark.parametrize("width", [16, 24])
def test_get_engine_caches_supported_widths(width: int) -> None:
    """A supported width yields the same engine instance on repeated calls."""
    assert POSEIDON._get_engine(width) is POSEIDON._get_engine(width)


@pytest.mark.parametrize("width", [0, 8, 15, 17, 32])
def test_get_engine_rejects_unsupported_width(width: int) -> None:
    """An unsupported width raises with the offending value named."""
    with pytest.raises(ValueError) as exception_info:
        POSEIDON._get_engine(width)
    assert str(exception_info.value) == f"Width must be 16 or 24, got {width}"


@pytest.mark.parametrize("width", [16, 24])
def test_compress_returns_requested_output_length(width: int) -> None:
    """Compression returns exactly the requested number of output elements."""
    compressed = POSEIDON.compress([Fp(value=i) for i in range(8)], width, 8)
    assert len(compressed) == 8


def test_compress_truncates_to_short_output() -> None:
    """A short output length yields a truncated digest."""
    compressed = POSEIDON.compress([Fp(value=i) for i in range(8)], 16, 1)
    assert len(compressed) == 1


def test_compress_is_deterministic() -> None:
    """The same input compresses to the same output."""
    first_compression = POSEIDON.compress([Fp(value=i) for i in range(8)], 16, 8)
    second_compression = POSEIDON.compress([Fp(value=i) for i in range(8)], 16, 8)
    assert first_compression == second_compression


def test_compress_rejects_output_longer_than_input() -> None:
    """Requesting more output than the raw input length raises."""
    with pytest.raises(ValueError) as exception_info:
        POSEIDON.compress([Fp(value=1), Fp(value=2)], 16, 8)
    assert str(exception_info.value) == "Input vector is too short for requested output length."


def test_safe_domain_separator_returns_capacity_length() -> None:
    """The domain separator returns a vector of the requested capacity length."""
    assert len(POSEIDON.safe_domain_separator([5, 2, 4, 8], 9)) == 9


def test_safe_domain_separator_distinguishes_shapes() -> None:
    """Different length parameters produce different capacity values."""
    assert POSEIDON.safe_domain_separator([1, 2], 9) != POSEIDON.safe_domain_separator([2, 1], 9)


def test_sponge_returns_requested_output_length() -> None:
    """The sponge returns exactly the requested number of output elements."""
    capacity = POSEIDON.safe_domain_separator([1, 2, 3, 4], 9)
    assert len(POSEIDON.sponge([Fp(value=1)] * 5, capacity, 8, 24)) == 8


def test_sponge_squeezes_more_than_one_rate_block() -> None:
    """Requesting more output than one rate block permutes again to squeeze enough."""
    capacity = POSEIDON.safe_domain_separator([1, 2, 3, 4], 9)
    rate = 24 - len(capacity)
    assert len(POSEIDON.sponge([Fp(value=1)] * 5, capacity, rate + 1, 24)) == rate + 1


def test_sponge_rejects_capacity_not_smaller_than_width() -> None:
    """A capacity that fills the whole state leaves no rate slot and raises."""
    with pytest.raises(ValueError) as exception_info:
        POSEIDON.sponge([Fp(value=1)], [Fp(value=0)] * 16, 1, 16)
    assert str(exception_info.value) == "Capacity length must be smaller than the state width."


def test_tweak_hash_chain_uses_width_sixteen_compression() -> None:
    """A single digest input hashes through width-sixteen compression."""
    hashed_digest = POSEIDON.tweak_hash(
        TEST_CONFIG,
        _parameter(),
        ChainTweak(epoch=Uint64(0), chain_index=1, step=1),
        [random_domain(TEST_CONFIG)],
    )
    assert isinstance(hashed_digest, HashDigestVector)
    assert len(hashed_digest.data) == TEST_CONFIG.HASH_LENGTH_FIELD_ELEMENTS


def test_tweak_hash_node_uses_width_twenty_four_compression() -> None:
    """Two digest inputs hash through width-twenty-four compression."""
    hashed_digest = POSEIDON.tweak_hash(
        TEST_CONFIG,
        _parameter(),
        TreeTweak(level=1, index=Uint64(0)),
        [random_domain(TEST_CONFIG), random_domain(TEST_CONFIG)],
    )
    assert len(hashed_digest.data) == TEST_CONFIG.HASH_LENGTH_FIELD_ELEMENTS


def test_tweak_hash_leaf_uses_sponge_mode() -> None:
    """More than two digest inputs hash through sponge mode."""
    leaf_digests = [random_domain(TEST_CONFIG) for _ in range(TEST_CONFIG.DIMENSION)]
    hashed_digest = POSEIDON.tweak_hash(
        TEST_CONFIG, _parameter(), TreeTweak(level=0, index=Uint64(0)), leaf_digests
    )
    assert len(hashed_digest.data) == TEST_CONFIG.HASH_LENGTH_FIELD_ELEMENTS


def test_tweak_hash_chain_and_tree_tweaks_are_domain_separated() -> None:
    """A chain tweak and a tree tweak over one digest produce different hashes."""
    digest = random_domain(TEST_CONFIG)
    chain = POSEIDON.tweak_hash(
        TEST_CONFIG, _parameter(), ChainTweak(epoch=Uint64(0), chain_index=0, step=1), [digest]
    )
    # A single-part tree tweak still routes through width-sixteen compression.
    tree = POSEIDON.tweak_hash(
        TEST_CONFIG, _parameter(), TreeTweak(level=0, index=Uint64(0)), [digest]
    )
    assert chain != tree


def test_hash_chain_zero_steps_returns_start_digest() -> None:
    """Walking zero steps returns the starting digest unchanged."""
    start_digest = random_domain(TEST_CONFIG)
    walked_digest = POSEIDON.hash_chain(
        config=TEST_CONFIG,
        parameter=_parameter(),
        epoch=Uint64(0),
        chain_index=0,
        start_step=0,
        num_steps=0,
        start_digest=start_digest,
    )
    assert walked_digest == start_digest


def test_hash_chain_is_composable() -> None:
    """Walking two steps equals walking one step then one more."""
    parameter = _parameter()
    start_digest = random_domain(TEST_CONFIG)
    walked_two_steps = POSEIDON.hash_chain(
        config=TEST_CONFIG,
        parameter=parameter,
        epoch=Uint64(0),
        chain_index=0,
        start_step=0,
        num_steps=2,
        start_digest=start_digest,
    )
    walked_one_step = POSEIDON.hash_chain(
        config=TEST_CONFIG,
        parameter=parameter,
        epoch=Uint64(0),
        chain_index=0,
        start_step=0,
        num_steps=1,
        start_digest=start_digest,
    )
    walked_one_more_step = POSEIDON.hash_chain(
        config=TEST_CONFIG,
        parameter=parameter,
        epoch=Uint64(0),
        chain_index=0,
        start_step=1,
        num_steps=1,
        start_digest=walked_one_step,
    )
    assert walked_two_steps == walked_one_more_step
