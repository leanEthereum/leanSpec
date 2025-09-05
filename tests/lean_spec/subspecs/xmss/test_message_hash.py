"""
Tests for the "Top Level" message hashing and encoding logic.
"""

from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss.constants import (
    TEST_CONFIG,
    TWEAK_PREFIX_MESSAGE,
)
from lean_spec.subspecs.xmss.message_hash import (
    TEST_MESSAGE_HASHER,
)
from lean_spec.subspecs.xmss.utils import TEST_RAND, int_to_base_p


def test_encode_message() -> None:
    """Tests `encode_message` with various message patterns."""
    config = TEST_CONFIG
    hasher = TEST_MESSAGE_HASHER

    # All-zero message
    msg_zeros = b"\x00" * config.MESSAGE_LENGTH
    encoded_zeros = hasher.encode_message(msg_zeros)
    assert len(encoded_zeros) == config.MSG_LEN_FE
    assert all(fe.value == 0 for fe in encoded_zeros)

    # All-max message (0xff)
    msg_max = b"\xff" * config.MESSAGE_LENGTH
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
        assert hasher.encode_epoch(epoch) == expected

    # Test for injectivity. It is highly unlikely for a collision to occur
    # with a few random samples if the encoding is injective.
    num_trials = 1000
    seen_encodings: set[tuple[Fp, ...]] = set()
    for i in range(num_trials):
        encoding = tuple(hasher.encode_epoch(i))
        assert encoding not in seen_encodings
        seen_encodings.add(encoding)


def test_apply_output_is_in_correct_hypercube_part() -> None:
    """
    Tests that the output of `apply` is a valid vertex that lies within
    the top `FINAL_LAYER` layers of the hypercube.
    """
    config = TEST_CONFIG
    hasher = TEST_MESSAGE_HASHER
    rand = TEST_RAND

    # Setup with random inputs.
    parameter = rand.parameter()
    epoch = 313
    randomness = rand.rho()
    message = b"\xaa" * config.MESSAGE_LENGTH

    # Call the message hash function.
    vertex = hasher.apply(parameter, epoch, randomness, message)

    # Verify the properties of the output vertex.
    #
    # The length of the vertex must be equal to the hypercube's dimension.
    assert len(vertex) == config.DIMENSION
    # Each coordinate must be smaller than the base `w`.
    assert all(0 <= coord < config.BASE for coord in vertex)

    # Check that the vertex lies in the correct set of layers.
    #
    # By definition, a vertex is in layer `d` if `d = v*(w-1) - sum(coords)`.
    #
    # We require `d <= FINAL_LAYER`.
    #
    # This is equivalent to `sum(coords) >= v*(w-1) - FINAL_LAYER`.
    coord_sum = sum(vertex)
    min_required_sum = (config.BASE - 1) * config.DIMENSION - config.FINAL_LAYER

    assert coord_sum >= min_required_sum, "Vertex is not in the top layers"
