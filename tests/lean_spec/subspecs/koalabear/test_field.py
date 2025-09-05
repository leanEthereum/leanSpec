"""
Tests for the KoalaBear prime field Fp.
"""

import pytest

from lean_spec.subspecs.koalabear.field import (
    TWO_ADIC_GENERATORS,
    TWO_ADICITY,
    Fp,
    P,
)


def test_constants() -> None:
    """Verify field constants."""
    assert P == 2**31 - 2**24 + 1
    assert (P - 1) % (2**TWO_ADICITY) == 0
    assert (P - 1) % (2 ** (TWO_ADICITY + 1)) != 0
    assert len(TWO_ADIC_GENERATORS) == TWO_ADICITY + 1


def test_base_field_arithmetic() -> None:
    """
    Test basic arithmetic, equality, and error handling
    in the base field Fp.
    """
    a = Fp(value=5)
    b = Fp(value=10)

    # Test operations
    assert a + b == Fp(value=15)
    assert b - a == Fp(value=5)
    assert -a == Fp(value=P - 5)
    assert a * b == Fp(value=50)
    assert a / b == Fp(value=5) * Fp(value=10).inverse()

    # Test equality against the same and different types
    assert a == Fp(value=5)
    assert a != b
    assert a != 5  # type: ignore[comparison-overlap]
    assert a != "5"  # type: ignore[comparison-overlap]

    # Test error on inverting the zero element
    with pytest.raises(ZeroDivisionError, match="Cannot invert the zero element."):
        Fp(value=0).inverse()


def test_two_adicity() -> None:
    """Test the properties and error handling of the two-adic generators."""
    bits = 4  # 2^4 = 16
    gen = Fp.two_adic_generator(bits)
    assert gen == Fp(value=TWO_ADIC_GENERATORS[bits])

    # Check that the generator has the correct order
    assert gen ** (2**bits) == Fp(value=1)
    assert gen ** (2 ** (bits - 1)) != Fp(value=1)

    # Check relationship between generators: g_n^2 should equal g_{n-1}
    gen_n = Fp.two_adic_generator(TWO_ADICITY)
    gen_n_minus_1 = Fp.two_adic_generator(TWO_ADICITY - 1)
    assert gen_n**2 == gen_n_minus_1

    # The largest order generator should square to -1
    assert gen_n ** (2 ** (TWO_ADICITY - 1)) == Fp(value=-1)

    # Test error handling for out-of-bounds input
    with pytest.raises(ValueError, match=f"bits must be between 0 and {TWO_ADICITY}"):
        Fp.two_adic_generator(TWO_ADICITY + 1)

    with pytest.raises(ValueError, match=f"bits must be between 0 and {TWO_ADICITY}"):
        Fp.two_adic_generator(-1)
