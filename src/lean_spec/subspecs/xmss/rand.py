"""Random data generator for the XMSS signature scheme."""

import secrets
from typing import List

from pydantic import model_validator

from lean_spec.types import StrictBaseModel

from ..koalabear import Fp, P
from .constants import PROD_CONFIG, TEST_CONFIG, XmssConfig
from .containers import HashDigest, Parameter, Randomness


class Rand(StrictBaseModel):
    """An instance of the random data generator for a given config."""

    config: XmssConfig
    """Configuration parameters for the random generator."""

    @model_validator(mode="after")
    def enforce_strict_types(self) -> "Rand":
        """Validates that only exact approved types are used (rejects subclasses)."""
        if type(self.config) is not XmssConfig:
            raise TypeError(f"config must be exactly XmssConfig, got {type(self.config).__name__}")
        return self

    def field_elements(self, length: int) -> List[Fp]:
        """Generates a random list of field elements."""
        # For each element, generate a secure random integer in the range [0, P-1].
        return [Fp(value=secrets.randbelow(P)) for _ in range(length)]

    def parameter(self) -> Parameter:
        """Generates a random public parameter."""
        return self.field_elements(self.config.PARAMETER_LEN)

    def domain(self) -> HashDigest:
        """Generates a random hash digest."""
        return self.field_elements(self.config.HASH_LEN_FE)

    def rho(self) -> Randomness:
        """Generates randomness `rho` for message encoding."""
        return self.field_elements(self.config.RAND_LEN_FE)


PROD_RAND = Rand(config=PROD_CONFIG)
"""An instance configured for production-level parameters."""

TEST_RAND = Rand(config=TEST_CONFIG)
"""A lightweight instance for test environments."""
