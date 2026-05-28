"""Field-element decomposition and secure sampling for the Generalized XMSS scheme."""

import secrets

from ..koalabear import Fp, P
from .constants import XmssConfig
from .types import HashDigestVector, Parameter


def int_to_base_p(value: int, num_limbs: int) -> list[Fp]:
    """Decompose an integer into a fixed-size list of base-P field elements."""
    acc = value
    limbs: list[Fp] = []
    for _ in range(num_limbs):
        limbs.append(Fp(value=acc))
        acc //= P
    return limbs


def random_field_elements(length: int) -> list[Fp]:
    """Sample a list of secure-random field elements in [0, P)."""
    return [Fp(value=secrets.randbelow(P)) for _ in range(length)]


def random_parameter(config: XmssConfig) -> Parameter:
    """Sample a fresh public parameter for one XMSS key pair."""
    return Parameter(data=random_field_elements(config.PARAMETER_LEN))


def random_domain(config: XmssConfig) -> HashDigestVector:
    """Sample a fresh hash-digest-sized vector of field elements."""
    return HashDigestVector(data=random_field_elements(config.HASH_LEN_FE))
