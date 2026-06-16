"""Tests for the SHAKE128-based pseudorandom function (PRF)."""

from lean_spec.spec.crypto.koalabear import Fp, P
from lean_spec.spec.crypto.xmss.constants import (
    PRF_KEY_LENGTH,
    TEST_CONFIG,
)
from lean_spec.spec.crypto.xmss.prf import PRFKey
from lean_spec.spec.ssz import Bytes32, Uint64


def test_key_gen_is_random() -> None:
    """Freshly generated keys have the fixed length, are all distinct, and never trivial."""
    # A freshly generated key has the fixed key length.
    key = PRFKey.generate()
    assert len(key) == PRF_KEY_LENGTH

    # Generate many keys and require every one to be distinct.
    #
    # The set size equals the trial count only when no two keys collide.
    # This proves the generator is not deterministic across calls.
    num_trials = 10
    keys = {PRFKey.generate() for _ in range(num_trials)}
    assert len(keys) == num_trials

    # No generated key is a single byte repeated.
    #
    # A secure random generator producing such a key is astronomically unlikely.
    assert all(len(set(key)) > 1 for key in keys)


def test_apply_is_sensitive_to_inputs() -> None:
    """Changing any single input to chain-start derivation changes the output."""
    config = TEST_CONFIG

    # Generate a baseline output with a set of initial inputs.
    key1 = PRFKey(b"\x11" * PRF_KEY_LENGTH)
    epoch1 = Uint64(10)
    chain_index1 = Uint64(20)
    baseline_output = key1.derive_chain_start(config, epoch1, chain_index1)
    assert len(baseline_output) == config.HASH_LENGTH_FIELD_ELEMENTS

    # Test sensitivity to the key.
    key2 = PRFKey(b"\x22" * PRF_KEY_LENGTH)
    output_key_changed = key2.derive_chain_start(config, epoch1, chain_index1)
    assert baseline_output != output_key_changed

    # Test sensitivity to the epoch.
    epoch2 = Uint64(11)
    output_epoch_changed = key1.derive_chain_start(config, epoch2, chain_index1)
    assert baseline_output != output_epoch_changed

    # Test sensitivity to the chain_index.
    chain_index2 = Uint64(21)
    output_index_changed = key1.derive_chain_start(config, epoch1, chain_index2)
    assert baseline_output != output_index_changed


def test_derive_randomness_output_shape_is_valid() -> None:
    """
    Tests that signing randomness has the configured length and valid field elements.

    Every element must be a field element inside the KoalaBear field range.
    """
    config = TEST_CONFIG

    key = PRFKey(b"\x11" * PRF_KEY_LENGTH)
    epoch = Uint64(10)
    message = Bytes32(b"\x33" * 32)
    counter = Uint64(0)
    randomness = key.derive_randomness(config, epoch, message, counter)

    # The vector length matches the configured number of randomness field elements.
    assert len(randomness) == config.RAND_LENGTH_FIELD_ELEMENTS

    # Each element is a field element normalized into the KoalaBear range.
    for field_element in randomness:
        assert isinstance(field_element, Fp)
        assert 0 <= field_element < P


def test_derive_randomness_is_deterministic() -> None:
    """
    Tests that identical inputs always reproduce the same signing randomness.

    Deterministic randomness keeps the signing attempt order reproducible.
    """
    config = TEST_CONFIG

    key = PRFKey(b"\x11" * PRF_KEY_LENGTH)
    epoch = Uint64(10)
    message = Bytes32(b"\x33" * 32)
    counter = Uint64(5)

    first_randomness = key.derive_randomness(config, epoch, message, counter)
    second_randomness = key.derive_randomness(config, epoch, message, counter)
    assert first_randomness == second_randomness


def test_derive_randomness_is_sensitive_to_inputs() -> None:
    """
    Tests that changing any input to randomness derivation changes the output.

    This confirms that the key, epoch, message, and counter are all absorbed.
    """
    config = TEST_CONFIG

    # Generate a baseline output with a set of initial inputs.
    baseline_key = PRFKey(b"\x11" * PRF_KEY_LENGTH)
    baseline_epoch = Uint64(10)
    baseline_message = Bytes32(b"\x33" * 32)
    baseline_counter = Uint64(0)
    baseline_randomness = baseline_key.derive_randomness(
        config, baseline_epoch, baseline_message, baseline_counter
    )

    # Test sensitivity to the key.
    changed_key = PRFKey(b"\x22" * PRF_KEY_LENGTH)
    randomness_key_changed = changed_key.derive_randomness(
        config, baseline_epoch, baseline_message, baseline_counter
    )
    assert baseline_randomness != randomness_key_changed

    # Test sensitivity to the epoch.
    changed_epoch = Uint64(11)
    randomness_epoch_changed = baseline_key.derive_randomness(
        config, changed_epoch, baseline_message, baseline_counter
    )
    assert baseline_randomness != randomness_epoch_changed

    # Test sensitivity to the message.
    changed_message = Bytes32(b"\x44" * 32)
    randomness_message_changed = baseline_key.derive_randomness(
        config, baseline_epoch, changed_message, baseline_counter
    )
    assert baseline_randomness != randomness_message_changed

    # Test sensitivity to the counter.
    changed_counter = Uint64(1)
    randomness_counter_changed = baseline_key.derive_randomness(
        config, baseline_epoch, baseline_message, changed_counter
    )
    assert baseline_randomness != randomness_counter_changed


def test_derive_randomness_is_domain_separated_from_chain_start() -> None:
    """
    Tests that chain-start and randomness derivation differ under aligned inputs.

    A distinct subdomain tag separates the two derivations even when the key and epoch match.
    The chain-start input mixes a chain index while randomness mixes a message and counter.
    A shared zero message and zero index align those mixed fields byte-for-byte.
    The remaining difference is only the subdomain tag.
    """
    config = TEST_CONFIG

    shared_key = PRFKey(b"\x11" * PRF_KEY_LENGTH)
    shared_epoch = Uint64(10)

    # The chain index is zero and the message and counter are zero.
    # With those mixed fields aligned, only the subdomain tag distinguishes the inputs.
    chain_start = shared_key.derive_chain_start(config, shared_epoch, Uint64(0))
    randomness = shared_key.derive_randomness(
        config, shared_epoch, Bytes32(b"\x00" * 32), Uint64(0)
    )

    # Compare the overlapping prefix so the difference is the tag, not the output length.
    shared_prefix_length = min(config.HASH_LENGTH_FIELD_ELEMENTS, config.RAND_LENGTH_FIELD_ELEMENTS)
    assert list(chain_start)[:shared_prefix_length] != list(randomness)[:shared_prefix_length]
