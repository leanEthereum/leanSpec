"""
Tests for the message hashing and aborting hypercube encoding logic.
"""

from lean_spec.subspecs.koalabear import Fp, P
from lean_spec.subspecs.xmss.constants import (
    TEST_CONFIG,
    TWEAK_PREFIX_MESSAGE,
)
from lean_spec.subspecs.xmss.message_hash import (
    TEST_MESSAGE_HASHER,
)
from lean_spec.subspecs.xmss.rand import TEST_RAND
from lean_spec.subspecs.xmss.utils import int_to_base_p
from lean_spec.types import Bytes32, Uint64


def test_encode_message() -> None:
    """Tests `encode_message` with various message patterns."""
    config = TEST_CONFIG
    hasher = TEST_MESSAGE_HASHER

    # All-zero message
    msg_zeros = Bytes32(b"\x00" * 32)
    encoded_zeros = hasher.encode_message(msg_zeros)
    assert len(encoded_zeros) == config.MSG_LEN_FE
    assert all(fe.value == 0 for fe in encoded_zeros)

    # All-max message (0xff)
    msg_max = Bytes32(b"\xff" * 32)
    acc = int.from_bytes(msg_max, "little")
    expected_max = int_to_base_p(acc, config.MSG_LEN_FE)
    assert hasher.encode_message(msg_max) == expected_max


def test_encode_epoch() -> None:
    """
    Tests `encode_epoch` for correctness and injectivity.
    """
    hasher = TEST_MESSAGE_HASHER
    config = TEST_CONFIG

    # Test specific values from the Rust reference tests.
    test_epochs = [0, 42, 2**32 - 1]
    for epoch in test_epochs:
        acc = (epoch << 8) | TWEAK_PREFIX_MESSAGE.value
        expected = int_to_base_p(acc, config.TWEAK_LEN_FE)
        assert hasher.encode_epoch(Uint64(epoch)) == expected

    # Test for injectivity. It is highly unlikely for a collision to occur
    # with a few random samples if the encoding is injective.
    num_trials = 1000
    seen_encodings: set[tuple[Fp, ...]] = set()
    for i in range(num_trials):
        encoding = tuple(hasher.encode_epoch(Uint64(i)))
        assert encoding not in seen_encodings
        seen_encodings.add(encoding)


def test_aborting_decode_known_decomposition() -> None:
    """Verifies aborting decode with a hand-computed example."""
    hasher = TEST_MESSAGE_HASHER
    config = TEST_CONFIG

    # Pick an arbitrary quotient multiplier to build a valid field element.
    d_value = 5
    fe_list = [Fp(value=config.Q * d_value)] * hasher.config.MH_HASH_LEN_FE
    result = hasher._aborting_decode(fe_list)
    assert result is not None
    assert len(result) == config.DIMENSION

    # Each FE decomposes d_value into Z base-BASE digits (LSB first),
    # then the first DIMENSION digits are taken across all FEs.
    digits_per_fe = []
    remaining = d_value
    for _ in range(config.Z):
        digits_per_fe.append(remaining % config.BASE)
        remaining //= config.BASE
    all_digits = (digits_per_fe * hasher.config.MH_HASH_LEN_FE)[: config.DIMENSION]
    assert result == all_digits


def test_aborting_decode_boundary() -> None:
    """Tests that FE = P-2 succeeds and FE = P-1 aborts."""
    hasher = TEST_MESSAGE_HASHER
    config = TEST_CONFIG

    # P - 2 is the largest valid value (just below Q * BASE^Z = P - 1).
    fe_valid = [Fp(value=P - 2)] * hasher.config.MH_HASH_LEN_FE
    result = hasher._aborting_decode(fe_valid)
    assert result is not None
    assert len(result) == config.DIMENSION
    assert all(0 <= d < config.BASE for d in result)

    # P - 1 triggers the abort (A_i >= Q * BASE^Z).
    fe_abort = [Fp(value=P - 1)]
    result = hasher._aborting_decode(fe_abort)
    assert result is None


def test_apply_output_is_valid_codeword() -> None:
    """
    Tests that the output of `apply` is `None` or a valid codeword with
    DIMENSION digits each in `[0, BASE-1]`.
    """
    config = TEST_CONFIG
    hasher = TEST_MESSAGE_HASHER
    rand = TEST_RAND

    # Setup with random inputs.
    parameter = rand.parameter()
    epoch = Uint64(313)
    randomness = rand.rho()
    message = Bytes32(b"\xaa" * 32)

    # Call the message hash function.
    result = hasher.apply(parameter, epoch, randomness, message)

    # The aborting decode may return None, but in practice it almost never does.
    assert result is not None

    # Verify the properties of the output codeword.
    assert len(result) == config.DIMENSION
    assert all(0 <= coord < config.BASE for coord in result)
