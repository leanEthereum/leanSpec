"""End-to-end tests for the Generalized XMSS signature scheme and its helpers."""

import pytest

from lean_spec.spec.crypto.xmss import interface
from lean_spec.spec.crypto.xmss.encoding import target_sum_encode
from lean_spec.spec.crypto.xmss.interface import (
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
    _expand_activation_time,
)
from lean_spec.spec.forks import Slot
from lean_spec.spec.ssz import Bytes32, Uint64


def _test_correctness_roundtrip(
    scheme: GeneralizedXmssScheme,
    activation_slot: int,
    num_active_slots: int,
) -> None:
    """
    A helper to perform a full key_gen -> sign -> verify roundtrip.

    It generates a key pair, signs a message at a specific slot, and
    verifies the signature. It also checks that verification fails for
    an incorrect message or slot.
    """
    # KEY GENERATION
    #
    # Generate a new key pair for the specified active range.
    kp = scheme.key_gen(Slot(activation_slot), Uint64(num_active_slots))
    public_key, secret_key = kp.public_key, kp.secret_key

    # SIGN & VERIFY
    #
    # Pick a sample slot within the active range to test signing.
    test_slot = Slot(activation_slot + num_active_slots // 2)
    message = Bytes32(b"\x42" * 32)

    # Sign the message at the chosen slot.
    #
    # This might take a moment as it may try multiple rho values.
    signature = scheme.sign(secret_key, test_slot, message)

    # Verification of the valid signature must succeed.
    is_valid = scheme.verify(public_key, test_slot, message, signature)
    assert is_valid, "Verification of a valid signature failed"

    # TEST INVALID CASES
    #
    # Verification must fail if the message is tampered with.
    tampered_message = Bytes32(b"\x43" * 32)

    # With small test parameters (test configuration), there's a small chance that
    # the tampered message produces the same codeword as the original due to
    # modular reduction collision.
    #
    # In that case, verification will succeed, which is expected behavior for identical codewords.
    #
    # We detect this by checking if both messages encode to the same codeword.
    original_codeword = target_sum_encode(
        scheme.poseidon, scheme.config, public_key.parameter, message, signature.rho, test_slot
    )
    tampered_codeword = target_sum_encode(
        scheme.poseidon,
        scheme.config,
        public_key.parameter,
        tampered_message,
        signature.rho,
        test_slot,
    )

    if tampered_codeword != original_codeword:
        # Different codewords: verification must fail
        is_invalid_message = scheme.verify(public_key, test_slot, tampered_message, signature)
        assert not is_invalid_message, "Verification succeeded for a tampered message"
    else:
        # Codeword collision: verification succeeds (expected with small test parameters)
        is_collision_valid = scheme.verify(public_key, test_slot, tampered_message, signature)
        assert is_collision_valid, "Verification failed despite identical codewords"

    # Verification must fail if the slot is incorrect.
    if num_active_slots > 1:
        wrong_slot = Slot(int(test_slot) + 1)
        is_invalid_slot = scheme.verify(public_key, wrong_slot, message, signature)
        assert not is_invalid_slot, "Verification succeeded for an incorrect slot"


@pytest.mark.parametrize(
    "activation_slot, num_active_slots",
    [
        pytest.param(
            4, 4, id="Standard case with a short, active lifetime", marks=pytest.mark.slow
        ),
        pytest.param(0, 8, id="Lifetime starting at slot 0", marks=pytest.mark.slow),
        pytest.param(7, 5, id="Lifetime starting at an odd-numbered slot", marks=pytest.mark.slow),
        pytest.param(12, 1, id="Lifetime with only a single active slot"),
    ],
)
def test_signature_scheme_correctness(activation_slot: int, num_active_slots: int) -> None:
    """Runs an end-to-end test of the signature scheme."""
    _test_correctness_roundtrip(
        scheme=TEST_SIGNATURE_SCHEME,
        activation_slot=activation_slot,
        num_active_slots=num_active_slots,
    )


def test_get_activation_interval() -> None:
    """Tests that get_activation_interval returns the correct range."""
    scheme = TEST_SIGNATURE_SCHEME
    # Use 8 slots (half of LIFETIME=16)
    secret_key = scheme.key_gen(Slot(4), Uint64(8)).secret_key

    interval = scheme.get_activation_interval(secret_key)

    # Verify it's a range
    assert isinstance(interval, range)

    # Verify it covers the activation interval (may be expanded)
    assert interval.start <= 4
    assert interval.stop >= 12


def test_get_prepared_interval() -> None:
    """Tests that get_prepared_interval returns the correct range."""
    scheme = TEST_SIGNATURE_SCHEME
    # Use full lifetime
    secret_key = scheme.key_gen(Slot(0), Uint64(16)).secret_key

    interval = scheme.get_prepared_interval(secret_key)

    # Verify it's a range
    assert isinstance(interval, range)

    # Verify it has at least 2 * sqrt(LIFETIME) slots
    leafs_per_bottom_tree = 1 << (scheme.config.LOG_LIFETIME // 2)
    min_prepared = 2 * leafs_per_bottom_tree
    assert len(interval) >= min_prepared


def test_advance_preparation() -> None:
    """Tests that advance_preparation correctly slides the window."""
    scheme = TEST_SIGNATURE_SCHEME
    # Request 3 bottom trees' worth of slots to ensure room to advance
    leafs_per_bottom_tree = 1 << (scheme.config.LOG_LIFETIME // 2)
    secret_key = scheme.key_gen(Slot(0), Uint64(3 * leafs_per_bottom_tree)).secret_key

    # Get initial prepared interval
    initial_interval = scheme.get_prepared_interval(secret_key)
    initial_left_index = secret_key.left_bottom_tree_index

    # Advance preparation (returns new SecretKey since models are immutable)
    secret_key = scheme.advance_preparation(secret_key)

    # Get new prepared interval
    new_interval = scheme.get_prepared_interval(secret_key)
    new_left_index = secret_key.left_bottom_tree_index

    # Verify the left index incremented
    assert new_left_index == initial_left_index + Uint64(1)

    # Verify the prepared interval shifted forward
    leafs_per_bottom_tree = 1 << (scheme.config.LOG_LIFETIME // 2)
    assert new_interval.start == initial_interval.start + leafs_per_bottom_tree
    assert new_interval.stop == initial_interval.stop + leafs_per_bottom_tree


def test_sign_requires_prepared_interval() -> None:
    """Tests that sign raises an error if slot is outside prepared interval."""
    scheme = TEST_SIGNATURE_SCHEME
    # Request 3 bottom trees' worth of slots to have room for testing
    leafs_per_bottom_tree = 1 << (scheme.config.LOG_LIFETIME // 2)
    secret_key = scheme.key_gen(Slot(0), Uint64(3 * leafs_per_bottom_tree)).secret_key

    # Get the prepared interval
    prepared_interval = scheme.get_prepared_interval(secret_key)

    # Try to sign outside the prepared interval (but inside activation interval)
    activation_interval = scheme.get_activation_interval(secret_key)
    # Pick an epoch just beyond the prepared interval
    outside_epoch = Slot(prepared_interval.stop)

    # Verify it's inside activation but outside prepared
    assert int(outside_epoch) in activation_interval
    assert int(outside_epoch) not in prepared_interval

    # Signing should fail
    message = Bytes32(b"\x42" * 32)
    with pytest.raises(ValueError, match="outside the prepared interval"):
        scheme.sign(secret_key, outside_epoch, message)


def test_deterministic_signing() -> None:
    """Tests that signing the same message with the same key produces the same signature."""
    scheme = TEST_SIGNATURE_SCHEME
    # Use full lifetime
    secret_key = scheme.key_gen(Slot(0), Uint64(16)).secret_key

    # Use epoch within prepared interval
    epoch = Slot(4)
    message = Bytes32(b"\x42" * 32)

    # Sign twice
    sig1 = scheme.sign(secret_key, epoch, message)
    sig2 = scheme.sign(secret_key, epoch, message)

    # Signatures should be identical (deterministic)
    assert sig1.rho == sig2.rho
    assert sig1.hashes == sig2.hashes
    assert sig1.path.siblings == sig2.path.siblings


@pytest.mark.parametrize(
    "log_lifetime, desired_activation, desired_num, expected_start, expected_end",
    [
        pytest.param(8, 0, 16, 0, 2, id="boundary request widens to minimum two trees"),
        pytest.param(8, 10, 5, 0, 2, id="unaligned request rounds onto tree boundaries"),
        pytest.param(8, 0, 100, 0, 7, id="larger request spans seven trees"),
        pytest.param(4, 0, 300, 0, 4, id="request wider than lifetime covers all of it"),
        pytest.param(8, 32, 16, 2, 4, id="middle request stays put"),
        pytest.param(8, 240, 30, 14, 16, id="request near the end slides back to the boundary"),
    ],
)
def test_expand_activation_time(
    log_lifetime: int,
    desired_activation: int,
    desired_num: int,
    expected_start: int,
    expected_end: int,
) -> None:
    """The requested window snaps onto whole bottom trees, widened and clamped."""
    assert _expand_activation_time(log_lifetime, desired_activation, desired_num) == (
        expected_start,
        expected_end,
    )


def test_key_gen_rejects_range_exceeding_lifetime() -> None:
    """A requested range past the lifetime is refused."""
    with pytest.raises(ValueError, match="Activation range exceeds the key's lifetime."):
        TEST_SIGNATURE_SCHEME.key_gen(Slot(200), Uint64(100))


def test_sign_rejects_slot_outside_activation() -> None:
    """Signing a slot the key was never activated for is refused."""
    secret_key = TEST_SIGNATURE_SCHEME.key_gen(Slot(0), Uint64(32)).secret_key
    with pytest.raises(ValueError, match="Key is not active for the specified slot."):
        TEST_SIGNATURE_SCHEME.sign(secret_key, Slot(200), Bytes32(b"\x42" * 32))


def test_sign_raises_when_no_encoding_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """An encoding search that never succeeds raises after exhausting the attempts.

    The encoding is forced to always reject so the retry loop runs to its limit.
    """
    secret_key = TEST_SIGNATURE_SCHEME.key_gen(Slot(0), Uint64(32)).secret_key
    monkeypatch.setattr(interface, "target_sum_encode", lambda *args, **kwargs: None)
    tries = TEST_SIGNATURE_SCHEME.config.MAX_TRIES
    with pytest.raises(
        RuntimeError, match=f"Failed to find a valid message encoding after {tries} tries."
    ):
        TEST_SIGNATURE_SCHEME.sign(secret_key, Slot(0), Bytes32(b"\x42" * 32))


def test_sign_raises_on_wrong_codeword_dimension(monkeypatch: pytest.MonkeyPatch) -> None:
    """An encoding returning the wrong number of digits raises.

    The encoding is forced to return one digit too few for the scheme dimension.
    """
    secret_key = TEST_SIGNATURE_SCHEME.key_gen(Slot(0), Uint64(32)).secret_key
    short = [0] * (TEST_SIGNATURE_SCHEME.config.DIMENSION - 1)
    monkeypatch.setattr(interface, "target_sum_encode", lambda *args, **kwargs: short)
    with pytest.raises(
        RuntimeError, match="Encoding is broken: returned too many or too few chunks."
    ):
        TEST_SIGNATURE_SCHEME.sign(secret_key, Slot(0), Bytes32(b"\x42" * 32))


def test_advance_preparation_is_a_noop_at_the_end() -> None:
    """A two-tree key cannot advance and returns the same secret key."""
    leaves = TEST_SIGNATURE_SCHEME.config.LEAVES_PER_BOTTOM_TREE
    secret_key = TEST_SIGNATURE_SCHEME.key_gen(Slot(0), Uint64(2 * leaves)).secret_key
    assert TEST_SIGNATURE_SCHEME.advance_preparation(secret_key) is secret_key


class TestVerifySecurityBounds:
    """
    Security tests for verify method input validation.

    Verification functions must return False (not raise) on attacker-controlled invalid input.
    This prevents denial-of-service via malformed signatures.
    """

    def test_rejects_slot_beyond_lifetime(self) -> None:
        """verify returns False when slot exceeds scheme LIFETIME."""
        scheme = TEST_SIGNATURE_SCHEME

        # Generate valid keys.
        kp = scheme.key_gen(Slot(0), Uint64(int(scheme.config.LIFETIME)))
        public_key, secret_key = kp.public_key, kp.secret_key

        # Sign a valid message at a valid epoch.
        valid_epoch = Slot(4)
        message = Bytes32(b"\x42" * 32)
        signature = scheme.sign(secret_key, valid_epoch, message)

        # Verify with an epoch beyond LIFETIME.
        invalid_epoch = Slot(int(scheme.config.LIFETIME) + 1)

        # Must return False, not raise.
        result = scheme.verify(public_key, invalid_epoch, message, signature)
        assert result is False

    def test_rejects_very_large_slot(self) -> None:
        """verify returns False for absurdly large slot values."""
        scheme = TEST_SIGNATURE_SCHEME
        kp = scheme.key_gen(Slot(0), Uint64(int(scheme.config.LIFETIME)))
        public_key, secret_key = kp.public_key, kp.secret_key

        valid_epoch = Slot(4)
        message = Bytes32(b"\x42" * 32)
        signature = scheme.sign(secret_key, valid_epoch, message)

        # Try to verify with a huge epoch.
        huge_epoch = Slot(2**32)

        # Must return False, not raise.
        result = scheme.verify(public_key, huge_epoch, message, signature)
        assert result is False
