"""Random data generator for the XMSS signature scheme."""

import secrets

from pydantic import model_validator

from lean_spec.types import StrictBaseModel

from ..koalabear import Fp, P
from .constants import PROD_CONFIG, TEST_CONFIG, XmssConfig
from .types import HashDigestVector, Parameter, Randomness


class Rand(StrictBaseModel):
    """An instance of the random data generator for a given config."""

    config: XmssConfig
    """Configuration parameters for the random generator."""

    @model_validator(mode="after")
    def enforce_strict_types(self) -> "Rand":
        """Reject subclasses to prevent type confusion attacks."""
        if type(self.config) is not XmssConfig:
            raise TypeError("config must be exactly XmssConfig, not a subclass")
        return self

    def field_elements(self, length: int) -> list[Fp]:
        """Generates a random list of field elements."""
        # For each element, generate a secure random integer in the range [0, P-1].
        return [Fp(value=secrets.randbelow(P)) for _ in range(length)]

    def parameter(self) -> Parameter:
        """Generates a random public parameter."""
        return Parameter(data=self.field_elements(self.config.PARAMETER_LEN))

    def domain(self) -> HashDigestVector:
        """Generates a random hash digest."""
        return HashDigestVector(data=self.field_elements(self.config.HASH_LEN_FE))

    def rho(self) -> Randomness:
        """Generates randomness `rho` for message encoding."""
        return Randomness(data=self.field_elements(self.config.RAND_LEN_FE))


PROD_RAND = Rand(config=PROD_CONFIG)
"""An instance configured for production-level parameters."""

TEST_RAND = Rand(config=TEST_CONFIG)
"""A lightweight instance for test environments."""
