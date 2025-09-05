"""
End-to-end tests for the Generalized XMSS signature scheme.
"""

import pytest

from lean_spec.subspecs.xmss.interface import (
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
)


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
    pk, sk = scheme.key_gen(activation_epoch, num_active_epochs)

    # SIGN & VERIFY
    #
    # Pick a sample epoch within the active range to test signing.
    test_epoch = activation_epoch + num_active_epochs // 2
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
    is_invalid_msg = scheme.verify(pk, test_epoch, tampered_message, signature)
    assert not is_invalid_msg, "Verification succeeded for a tampered message"

    # Verification must fail if the epoch is incorrect.
    if num_active_epochs > 1:
        wrong_epoch = test_epoch + 1
        is_invalid_epoch = scheme.verify(pk, wrong_epoch, message, signature)
        assert not is_invalid_epoch, "Verification succeeded for an incorrect epoch"


@pytest.mark.parametrize(
    "activation_epoch, num_active_epochs, description",
    [
        (10, 4, "Standard case with a short, active lifetime"),
        (0, 8, "Lifetime starting at epoch 0"),
        (20, 1, "Lifetime with only a single active epoch"),
        (7, 5, "Lifetime starting at an odd-numbered epoch"),
    ],
)
def test_signature_scheme_correctness(
    activation_epoch: int, num_active_epochs: int, description: str
) -> None:
    """Runs an end-to-end test of the signature scheme."""
    _test_correctness_roundtrip(
        scheme=TEST_SIGNATURE_SCHEME,
        activation_epoch=activation_epoch,
        num_active_epochs=num_active_epochs,
    )
