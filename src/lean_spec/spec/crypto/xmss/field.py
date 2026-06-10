"""Field-element decomposition and secure sampling for the Generalized XMSS scheme."""

import secrets

from lean_spec.spec.crypto.koalabear import Fp, P
from lean_spec.spec.crypto.xmss.constants import XmssConfig
from lean_spec.spec.crypto.xmss.types import HashDigestVector, Parameter


def int_to_base_p(value: int, num_limbs: int) -> list[Fp]:
    """
    Decompose a non-negative integer into a fixed-size list of base-P field elements.

    The integer must be small enough to fit in the requested number of limbs.

    Raises:
        ValueError: When the integer is too large to fit in the requested limbs.
    """
    remaining_value = value
    limbs: list[Fp] = []
    for _ in range(num_limbs):
        limbs.append(Fp(value=remaining_value))
        remaining_value //= P

    # A nonzero remainder means the integer was wider than the requested limbs.
    # Dropping the high part would silently change the resulting hash.
    # Reject it instead of returning a truncated decomposition.
    if remaining_value != 0:
        raise ValueError(f"value does not fit in {num_limbs} base-P limbs")

    return limbs


def random_field_elements(length: int) -> list[Fp]:
    """Sample a list of secure-random field elements in [0, P)."""
    return [Fp(value=secrets.randbelow(P)) for _ in range(length)]


def random_parameter(config: XmssConfig) -> Parameter:
    """Sample a fresh public parameter for one XMSS key pair."""
    return Parameter(data=random_field_elements(config.PARAMETER_LENGTH))


def random_domain(config: XmssConfig) -> HashDigestVector:
    """Sample a fresh hash-digest-sized vector of field elements."""
    return HashDigestVector(data=random_field_elements(config.HASH_LENGTH_FIELD_ELEMENTS))
