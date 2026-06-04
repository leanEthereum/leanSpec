"""Tests for the message-to-codeword encoding pipeline."""

import pytest

from lean_spec.spec.crypto.koalabear import Fp, P
from lean_spec.spec.crypto.xmss import encoding
from lean_spec.spec.crypto.xmss.constants import TEST_CONFIG, TWEAK_PREFIX_MESSAGE
from lean_spec.spec.crypto.xmss.encoding import (
    aborting_decode,
    encode_epoch,
    encode_message,
    message_hash,
    target_sum_encode,
)
from lean_spec.spec.crypto.xmss.field import int_to_base_p, random_field_elements
from lean_spec.spec.crypto.xmss.poseidon import POSEIDON
from lean_spec.spec.crypto.xmss.types import Parameter, Randomness
from lean_spec.spec.ssz import Bytes32, Uint64


def _parameter() -> Parameter:
    """Return a fixed public parameter for encoding tests."""
    return Parameter(data=[Fp(value=1)] * TEST_CONFIG.PARAMETER_LENGTH)


def test_encode_message_zero_is_all_zero_limbs() -> None:
    """An all-zero message encodes to all-zero field elements."""
    encoded = encode_message(TEST_CONFIG, Bytes32(b"\x00" * 32))
    assert encoded == [Fp(value=0)] * TEST_CONFIG.MESSAGE_LENGTH_FIELD_ELEMENTS


def test_encode_message_reads_little_endian() -> None:
    """A maximal message encodes to its little-endian base-P decomposition."""
    message = Bytes32(b"\xff" * 32)
    acc = int.from_bytes(message, "little")
    assert encode_message(TEST_CONFIG, message) == int_to_base_p(
        acc, TEST_CONFIG.MESSAGE_LENGTH_FIELD_ELEMENTS
    )


@pytest.mark.parametrize("epoch", [0, 42, 2**32 - 1])
def test_encode_epoch_matches_prefixed_decomposition(epoch: int) -> None:
    """An epoch encodes to its value shifted above the message prefix."""
    acc = (epoch << 8) | TWEAK_PREFIX_MESSAGE
    expected = int_to_base_p(acc, TEST_CONFIG.TWEAK_LENGTH_FIELD_ELEMENTS)
    assert encode_epoch(TEST_CONFIG, Uint64(epoch)) == expected


def test_encode_epoch_is_injective_over_a_range() -> None:
    """Distinct epochs in a range encode to distinct field-element tuples."""
    encodings = {tuple(encode_epoch(TEST_CONFIG, Uint64(i))) for i in range(1000)}
    assert len(encodings) == 1000


def test_aborting_decode_known_decomposition() -> None:
    """A hand-built quotient decodes to its base-BASE digits, truncated to the dimension."""
    config = TEST_CONFIG
    d_value = 5
    field_element_list = [Fp(value=config.Q * d_value)] * config.MH_HASH_LENGTH_FIELD_ELEMENTS

    expected_per_field_element = []
    remaining = d_value
    for _ in range(config.Z):
        expected_per_field_element.append(remaining % config.BASE)
        remaining //= config.BASE
    expected = (expected_per_field_element * config.MH_HASH_LENGTH_FIELD_ELEMENTS)[
        : config.DIMENSION
    ]

    assert aborting_decode(config, field_element_list) == expected


def test_aborting_decode_accepts_largest_valid_element() -> None:
    """The element just below the abort threshold decodes successfully."""
    config = TEST_CONFIG
    result = aborting_decode(config, [Fp(value=P - 2)] * config.MH_HASH_LENGTH_FIELD_ELEMENTS)
    assert result is not None
    assert len(result) == config.DIMENSION
    assert all(0 <= d < config.BASE for d in result)


def test_aborting_decode_rejects_threshold_element() -> None:
    """The element equal to the prime minus one triggers the abort."""
    assert aborting_decode(TEST_CONFIG, [Fp(value=P - 1)]) is None


def test_message_hash_yields_valid_codeword() -> None:
    """The message hash decodes to a codeword of dimension digits in range."""
    config = TEST_CONFIG
    parameter = Parameter(data=random_field_elements(config.PARAMETER_LENGTH))
    randomness = Randomness(data=random_field_elements(config.RAND_LENGTH_FIELD_ELEMENTS))

    result = message_hash(
        POSEIDON, config, parameter, Uint64(313), randomness, Bytes32(b"\xaa" * 32)
    )

    assert result is not None
    assert len(result) == config.DIMENSION
    assert all(0 <= digit < config.BASE for digit in result)


def test_target_sum_encode_accepts_codeword_on_target_layer() -> None:
    """Randomness whose codeword sums to the target is accepted."""
    config = TEST_CONFIG
    parameter = _parameter()
    # Attempt counter three lands the all-zero message on the target-sum layer.
    rho = Randomness(data=int_to_base_p(3, config.RAND_LENGTH_FIELD_ELEMENTS))

    codeword = target_sum_encode(POSEIDON, config, parameter, Bytes32(b"\x00" * 32), rho, Uint64(0))

    # The digits sum to the target of six, landing on the accepted layer.
    assert codeword == [3, 0, 3, 0]


def test_target_sum_encode_rejects_codeword_off_target_layer() -> None:
    """Randomness whose codeword misses the target sum is rejected."""
    config = TEST_CONFIG
    parameter = _parameter()
    # Attempt counter zero produces a codeword whose digits do not sum to the target.
    rho = Randomness(data=int_to_base_p(0, config.RAND_LENGTH_FIELD_ELEMENTS))

    assert (
        target_sum_encode(POSEIDON, config, parameter, Bytes32(b"\x00" * 32), rho, Uint64(0))
        is None
    )


def test_target_sum_encode_propagates_aborting_decode_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An aborting message hash makes the encode return None before the sum check.

    The aborting decode rejects only the prime-minus-one field element.
    That event has probability near one in two billion per element.
    It cannot be triggered with real inputs in a test, so the hash result is forced.
    """
    monkeypatch.setattr(encoding, "message_hash", lambda *args, **kwargs: None)

    assert (
        target_sum_encode(
            POSEIDON,
            TEST_CONFIG,
            _parameter(),
            Bytes32(b"\x00" * 32),
            Randomness(data=int_to_base_p(0, TEST_CONFIG.RAND_LENGTH_FIELD_ELEMENTS)),
            Uint64(0),
        )
        is None
    )
