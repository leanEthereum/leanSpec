"""Tests for the field-element decomposition and secure sampling helpers."""

import secrets

import pytest

from lean_spec.spec.crypto.koalabear import Fp, P
from lean_spec.spec.crypto.xmss.constants import TEST_CONFIG
from lean_spec.spec.crypto.xmss.field import (
    int_to_base_p,
    random_domain,
    random_field_elements,
    random_parameter,
)
from lean_spec.spec.crypto.xmss.types import HashDigestVector, Parameter


@pytest.mark.parametrize(
    "integer_value, num_limbs, expected_limbs",
    [
        pytest.param(0, 4, [0, 0, 0, 0], id="zero spreads to all-zero limbs"),
        pytest.param(123, 4, [123, 0, 0, 0], id="small value in the lowest limb"),
        pytest.param(P, 4, [0, 1, 0, 0], id="prime carries into the second limb"),
        pytest.param(P - 1, 4, [P - 1, 0, 0, 0], id="largest single-limb value"),
        pytest.param(3 * (P**2) + 2 * P + 1, 4, [1, 2, 3, 0], id="mixed multi-limb value"),
        pytest.param(P**3 - 1, 3, [P - 1, P - 1, P - 1], id="all limbs saturated"),
    ],
)
def test_int_to_base_p_known_decomposition(
    integer_value: int, num_limbs: int, expected_limbs: list[int]
) -> None:
    """Decomposition matches hand-computed base-P limbs."""
    assert int_to_base_p(integer_value, num_limbs) == [Fp(value=limb) for limb in expected_limbs]


def test_int_to_base_p_zero_limbs_accepts_only_zero() -> None:
    """Zero fits in zero limbs and yields an empty list."""
    assert int_to_base_p(0, 0) == []


def test_int_to_base_p_rejects_overflow() -> None:
    """A value wider than the requested limbs is rejected, not truncated."""
    with pytest.raises(ValueError) as exception_info:
        int_to_base_p(P**2 + P + 7, 1)
    assert str(exception_info.value) == "value does not fit in 1 base-P limbs"

    with pytest.raises(ValueError) as exception_info:
        int_to_base_p(12345, 0)
    assert str(exception_info.value) == "value does not fit in 0 base-P limbs"


def test_int_to_base_p_roundtrip_is_reversible() -> None:
    """Decomposing then recomposing recovers the original integer."""
    num_limbs = 5
    original_limbs = [secrets.randbelow(P) for _ in range(num_limbs)]
    original_value = sum(limb * (P**i) for i, limb in enumerate(original_limbs))

    decomposed = [int(fp) for fp in int_to_base_p(original_value, num_limbs)]

    assert decomposed == original_limbs


def test_random_field_elements_length() -> None:
    """The sampler returns exactly the requested number of elements."""
    assert len(random_field_elements(7)) == 7


def test_random_field_elements_zero_length() -> None:
    """A zero-length request yields an empty list."""
    assert random_field_elements(0) == []


def test_random_field_elements_are_in_field_range() -> None:
    """Every sampled element lies in the range zero up to the prime."""
    assert all(0 <= int(fe) < P for fe in random_field_elements(50))


def test_random_field_elements_are_not_constant() -> None:
    """A large sample is overwhelmingly unlikely to repeat a single value."""
    assert len({int(fe) for fe in random_field_elements(100)}) > 1


def test_random_parameter_has_parameter_length() -> None:
    """A sampled parameter has the configured parameter length."""
    parameter = random_parameter(TEST_CONFIG)
    assert isinstance(parameter, Parameter)
    assert len(parameter.data) == TEST_CONFIG.PARAMETER_LENGTH


def test_random_domain_has_hash_length() -> None:
    """A sampled domain vector has the configured digest length."""
    domain = random_domain(TEST_CONFIG)
    assert isinstance(domain, HashDigestVector)
    assert len(domain.data) == TEST_CONFIG.HASH_LENGTH_FIELD_ELEMENTS
