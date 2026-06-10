"""Tests for the SHAKE128-based pseudorandom function (PRF)."""

from lean_spec.spec.crypto.xmss.constants import (
    PRF_KEY_LENGTH,
    TEST_CONFIG,
)
from lean_spec.spec.crypto.xmss.prf import PRFKey
from lean_spec.spec.ssz import Uint64


def test_key_gen_is_random() -> None:
    """
    Performs a sanity check on key_gen to ensure it's not deterministic
    or producing trivial outputs.

    This test mirrors the logic from the reference Rust implementation.
    """
    # Check that the key has the correct length.
    key = PRFKey.generate()
    assert len(key) == PRF_KEY_LENGTH

    # Generate multiple keys and ensure they are not all identical.
    #
    # This is a basic check to ensure we are getting fresh randomness.
    num_trials = 10
    keys = {PRFKey.generate() for _ in range(num_trials)}
    assert len(keys) == num_trials

    # Check that the keys are not filled with a single repeated byte.
    #
    # It is astronomically unlikely for a secure random generator to produce
    # such a key, so this is a good health check.
    all_same_count = 0
    for _ in range(num_trials):
        key = PRFKey.generate()
        # A set will have size 1 if all elements are the same.
        if len(set(key)) == 1:
            all_same_count += 1
    assert all_same_count < num_trials, "key_gen produced non-random keys"


def test_apply_is_sensitive_to_inputs() -> None:
    """
    Tests that changing any input to apply results in a different output.

    This confirms that all parts of the input (key, epoch, chain_index) are
    being correctly absorbed by the hash function.
    """
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
