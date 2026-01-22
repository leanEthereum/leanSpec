"""
End-to-end tests for the Generalized XMSS signature scheme.
"""

import pytest

from lean_spec.subspecs.xmss.interface import (
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
)
from lean_spec.types import Uint64


def _test_correctness_roundtrip(
    scheme: GeneralizedXmssScheme,
    activation_epoch: int,
    num_active_epochs: int,
) -> None:
    """
    A helper to perform a full key_gen -> sign -> verify roundtrip.

    It generates a key pair, signs a message at a specific epoch, and
    verifies the signature. It also checks that verification fails for
    an incorrect message or epoch.
    """
    # KEY GENERATION
    #
    # Generate a new key pair for the specified active range.
    pk, sk = scheme.key_gen(Uint64(activation_epoch), Uint64(num_active_epochs))

    # SIGN & VERIFY
    #
    # Pick a sample epoch within the active range to test signing.
    test_epoch = Uint64(activation_epoch + num_active_epochs // 2)
    message = b"\x42" * scheme.config.MESSAGE_LENGTH

    # Sign the message at the chosen epoch.
    #
    # This might take a moment as it may try multiple `rho` values.
    signature = scheme.sign(sk, test_epoch, message)

    # Verification of the valid signature must succeed.
    is_valid = scheme.verify(pk, test_epoch, message, signature)
    assert is_valid, "Verification of a valid signature failed"

    # TEST INVALID CASES
    #
    # Verification must fail if the message is tampered with.
    tampered_message = b"\x43" * scheme.config.MESSAGE_LENGTH

    # With small test parameters (test configuration), there's a small chance that
    # the tampered message produces the same codeword as the original due to
    # modular reduction collision.
    #
    # In that case, verification will succeed, which is expected behavior for identical codewords.
    #
    # We detect this by checking if both messages encode to the same codeword.
    original_codeword = scheme.encoder.encode(pk.parameter, message, signature.rho, test_epoch)
    tampered_codeword = scheme.encoder.encode(
        pk.parameter, tampered_message, signature.rho, test_epoch
    )

    if tampered_codeword != original_codeword:
        # Different codewords: verification must fail
        is_invalid_msg = scheme.verify(pk, test_epoch, tampered_message, signature)
        assert not is_invalid_msg, "Verification succeeded for a tampered message"
    else:
        # Codeword collision: verification succeeds (expected with small test parameters)
        is_collision_valid = scheme.verify(pk, test_epoch, tampered_message, signature)
        assert is_collision_valid, "Verification failed despite identical codewords"

    # Verification must fail if the epoch is incorrect.
    if num_active_epochs > 1:
        wrong_epoch = Uint64(int(test_epoch) + 1)
        is_invalid_epoch = scheme.verify(pk, wrong_epoch, message, signature)
        assert not is_invalid_epoch, "Verification succeeded for an incorrect epoch"


@pytest.mark.parametrize(
    "activation_epoch, num_active_epochs",
    [
        pytest.param(
            4, 4, id="Standard case with a short, active lifetime", marks=pytest.mark.slow
        ),
        pytest.param(0, 8, id="Lifetime starting at epoch 0", marks=pytest.mark.slow),
        pytest.param(7, 5, id="Lifetime starting at an odd-numbered epoch", marks=pytest.mark.slow),
        pytest.param(12, 1, id="Lifetime with only a single active epoch"),
    ],
)
def test_signature_scheme_correctness(activation_epoch: int, num_active_epochs: int) -> None:
    """Runs an end-to-end test of the signature scheme."""
    _test_correctness_roundtrip(
        scheme=TEST_SIGNATURE_SCHEME,
        activation_epoch=activation_epoch,
        num_active_epochs=num_active_epochs,
    )


def test_get_activation_interval() -> None:
    """Tests that get_activation_interval returns the correct range."""
    scheme = TEST_SIGNATURE_SCHEME
    # Use 8 epochs (half of LIFETIME=16)
    pk, sk = scheme.key_gen(Uint64(4), Uint64(8))

    interval = scheme.get_activation_interval(sk)

    # Verify it's a range
    assert isinstance(interval, range)

    # Verify it covers the activation interval (may be expanded)
    assert interval.start <= 4
    assert interval.stop >= 12


def test_get_prepared_interval() -> None:
    """Tests that get_prepared_interval returns the correct range."""
    scheme = TEST_SIGNATURE_SCHEME
    # Use full lifetime
    pk, sk = scheme.key_gen(Uint64(0), Uint64(16))

    interval = scheme.get_prepared_interval(sk)

    # Verify it's a range
    assert isinstance(interval, range)

    # Verify it has at least 2 * sqrt(LIFETIME) epochs
    leafs_per_bottom_tree = 1 << (scheme.config.LOG_LIFETIME // 2)
    min_prepared = 2 * leafs_per_bottom_tree
    assert len(interval) >= min_prepared


def test_advance_preparation() -> None:
    """Tests that advance_preparation correctly slides the window."""
    scheme = TEST_SIGNATURE_SCHEME
    # Request 3 bottom trees' worth of epochs to ensure room to advance
    leafs_per_bottom_tree = 1 << (scheme.config.LOG_LIFETIME // 2)
    pk, sk = scheme.key_gen(Uint64(0), Uint64(3 * leafs_per_bottom_tree))

    # Get initial prepared interval
    initial_interval = scheme.get_prepared_interval(sk)
    initial_left_index = sk.left_bottom_tree_index

    # Advance preparation (returns new SecretKey since models are immutable)
    sk = scheme.advance_preparation(sk)

    # Get new prepared interval
    new_interval = scheme.get_prepared_interval(sk)
    new_left_index = sk.left_bottom_tree_index

    # Verify the left index incremented
    assert new_left_index == initial_left_index + Uint64(1)

    # Verify the prepared interval shifted forward
    leafs_per_bottom_tree = 1 << (scheme.config.LOG_LIFETIME // 2)
    assert new_interval.start == initial_interval.start + leafs_per_bottom_tree
    assert new_interval.stop == initial_interval.stop + leafs_per_bottom_tree


def test_sign_requires_prepared_interval() -> None:
    """Tests that sign raises an error if epoch is outside prepared interval."""
    scheme = TEST_SIGNATURE_SCHEME
    # Request 3 bottom trees' worth of epochs to have room for testing
    leafs_per_bottom_tree = 1 << (scheme.config.LOG_LIFETIME // 2)
    pk, sk = scheme.key_gen(Uint64(0), Uint64(3 * leafs_per_bottom_tree))

    # Get the prepared interval
    prepared_interval = scheme.get_prepared_interval(sk)

    # Try to sign outside the prepared interval (but inside activation interval)
    activation_interval = scheme.get_activation_interval(sk)
    # Pick an epoch just beyond the prepared interval
    outside_epoch = Uint64(prepared_interval.stop)

    # Verify it's inside activation but outside prepared
    assert int(outside_epoch) in activation_interval
    assert int(outside_epoch) not in prepared_interval

    # Signing should fail
    message = b"\x42" * scheme.config.MESSAGE_LENGTH
    with pytest.raises(ValueError, match="outside the prepared interval"):
        scheme.sign(sk, outside_epoch, message)


def test_deterministic_signing() -> None:
    """Tests that signing the same message with the same key produces the same signature."""
    scheme = TEST_SIGNATURE_SCHEME
    # Use full lifetime
    pk, sk = scheme.key_gen(Uint64(0), Uint64(16))

    # Use epoch within prepared interval
    epoch = Uint64(4)
    message = b"\x42" * scheme.config.MESSAGE_LENGTH

    # Sign twice
    sig1 = scheme.sign(sk, epoch, message)
    sig2 = scheme.sign(sk, epoch, message)

    # Signatures should be identical (deterministic)
    assert sig1.rho == sig2.rho
    assert sig1.hashes == sig2.hashes
    assert sig1.path.siblings == sig2.path.siblings


class TestVerifySecurityBounds:
    """
    Security tests for verify method input validation.

    Verification functions must return False (not raise) on attacker-controlled invalid input.
    This prevents denial-of-service via malformed signatures.
    """

    def test_rejects_epoch_beyond_lifetime(self) -> None:
        """verify returns False when epoch exceeds scheme LIFETIME."""
        scheme = TEST_SIGNATURE_SCHEME

        # Generate valid keys.
        pk, sk = scheme.key_gen(Uint64(0), Uint64(scheme.config.LIFETIME))

        # Sign a valid message at a valid epoch.
        valid_epoch = Uint64(4)
        message = b"\x42" * scheme.config.MESSAGE_LENGTH
        signature = scheme.sign(sk, valid_epoch, message)

        # Verify with an epoch beyond LIFETIME.
        invalid_epoch = Uint64(int(scheme.config.LIFETIME) + 1)

        # Must return False, not raise.
        result = scheme.verify(pk, invalid_epoch, message, signature)
        assert result is False

    def test_rejects_very_large_epoch(self) -> None:
        """verify returns False for absurdly large epoch values."""
        scheme = TEST_SIGNATURE_SCHEME
        pk, sk = scheme.key_gen(Uint64(0), Uint64(scheme.config.LIFETIME))

        valid_epoch = Uint64(4)
        message = b"\x42" * scheme.config.MESSAGE_LENGTH
        signature = scheme.sign(sk, valid_epoch, message)

        # Try to verify with a huge epoch.
        huge_epoch = Uint64(2**32)

        # Must return False, not raise.
        result = scheme.verify(pk, huge_epoch, message, signature)
        assert result is False
