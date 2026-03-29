"""
Defines the message hashing for the signature scheme using aborting hypercube encoding.

### The Challenge: Efficiently Encoding a Message as a Codeword

The "Target Sum" signature scheme requires the signer to find a `codeword` whose
digits sum to a specific value. This requires hashing a message and mapping the
output to a vertex in a high-dimensional hypercube.

### The Solution: Aborting Hypercube Encoding

This module implements a circuit-friendly encoding based on rejection sampling of
individual field elements, eliminating all big-integer arithmetic.

For KoalaBear (`P = 2^31 - 2^24 + 1`), `P - 1 = Q * BASE^Z`, so each field element
can be decomposed into `Z` base-`BASE` digits after dividing by `Q`. The only reject
case is `A_i == P - 1` (probability ~4.7e-10 per FE — essentially never aborts).

This is backed by the "Aborting Random Oracles" paper which proves
indifferentiability from a theta-aborting random oracle when modeling Poseidon as a
standard random oracle.

The encoding proceeds in two stages:

1. **Input Preparation**: All inputs are encoded into field elements.
2. **Poseidon Hashing + Aborting Decode**: Poseidon1 produces `ceil(DIMENSION/Z)`
   field elements, each decoded into `Z` base-`BASE` digits via rejection sampling.
"""

from __future__ import annotations

from pydantic import model_validator

from lean_spec.subspecs.xmss.poseidon import (
    PROD_POSEIDON,
    TEST_POSEIDON,
    PoseidonXmss,
)
from lean_spec.types import Bytes32, StrictBaseModel, Uint64

from ..koalabear import Fp
from ._validation import enforce_strict_types
from .constants import (
    PROD_CONFIG,
    TEST_CONFIG,
    TWEAK_PREFIX_MESSAGE,
    XmssConfig,
)
from .types import Parameter, Randomness
from .utils import int_to_base_p


class MessageHasher(StrictBaseModel):
    """An instance of the message hasher using aborting hypercube encoding."""

    config: XmssConfig
    """Configuration parameters for the hasher."""

    poseidon: PoseidonXmss
    """Poseidon hash engine."""

    @model_validator(mode="after")
    def _validate_strict_types(self) -> MessageHasher:
        """Reject subclasses to prevent type confusion attacks."""
        enforce_strict_types(self, config=XmssConfig, poseidon=PoseidonXmss)
        return self

    def encode_message(self, message: Bytes32) -> list[Fp]:
        """
        Encodes a 32-byte message into a list of field elements.

        The message bytes are interpreted as a single little-endian integer,
        which is then decomposed into its base-`P` representation, where `P`
        is the field prime. This provides a canonical mapping from bytes to
        the algebraic structure required by Poseidon1.
        """
        # Interpret the 32 little-endian bytes as a single large integer.
        acc = int.from_bytes(message, "little")

        # Decompose the integer into a list of field elements (base-P).
        return int_to_base_p(acc, self.config.MSG_LEN_FE)

    def encode_epoch(self, epoch: Uint64) -> list[Fp]:
        """
        Encodes the epoch and a domain separator prefix into field elements.

        This function packs the epoch and the message hash prefix into a single
        integer, then decomposes it. This ensures the epoch is included in the
        hash input in a structured, domain-separated way.
        """
        # Combine the epoch and the message hash prefix into a single integer.
        acc = (int(epoch) << 8) | TWEAK_PREFIX_MESSAGE.value

        # Decompose the integer into its base-P representation.
        return int_to_base_p(acc, self.config.TWEAK_LEN_FE)

    def _aborting_decode(self, field_elements: list[Fp]) -> list[int] | None:
        """
        Decodes Poseidon output field elements into base-`BASE` digits via rejection sampling.

        For each field element `A_i`:

        1. If `A_i >= Q * BASE^Z` (i.e. `A_i == P - 1`), abort and return `None`.
        2. Compute `d_i = A_i // Q`, an integer in `[0, BASE^Z - 1]`.
        3. Decompose `d_i` into `Z` base-`BASE` digits, least significant first.

        Collect all digits and return the first `DIMENSION` of them.
        """
        config = self.config
        threshold = config.Q * config.BASE**config.Z

        digits: list[int] = []
        for fe in field_elements:
            a = fe.value

            # Rejection: the only failing case is A_i == P - 1.
            if a >= threshold:
                return None

            # Integer quotient removes the Q-residue, leaving a uniform value in [0, BASE^Z - 1].
            d = a // config.Q

            # Decompose d into Z base-BASE digits, least significant first.
            for _ in range(config.Z):
                digits.append(d % config.BASE)
                d //= config.BASE

        # Take exactly DIMENSION digits.
        return digits[: config.DIMENSION]

    def apply(
        self,
        parameter: Parameter,
        epoch: Uint64,
        rho: Randomness,
        message: Bytes32,
    ) -> list[int] | None:
        """
        Applies message hashing followed by aborting hypercube decode.

        Hashes the inputs with Poseidon1 to produce `MH_HASH_LEN_FE` field elements,
        then decodes them into a candidate codeword via rejection sampling.

        Args:
            parameter: The public parameter `P`.
            epoch: The current epoch.
            rho: A random value `rho` to ensure a unique hash output.
            message: The 32-byte message to be hashed.

        Returns:
            A candidate codeword (list of `DIMENSION` digits in `[0, BASE-1]`),
            or `None` if the aborting decode rejects.
        """
        # Encode the message and epoch as field elements.
        message_fe = self.encode_message(message)
        epoch_fe = self.encode_epoch(epoch)

        # Call Poseidon1 once to produce the required number of output field elements.
        base_input = message_fe + list(parameter.data) + epoch_fe + list(rho.data)
        poseidon_output = self.poseidon.compress(base_input, 24, self.config.MH_HASH_LEN_FE)

        # Decode the field elements into base-BASE digits via rejection sampling.
        return self._aborting_decode(poseidon_output)


PROD_MESSAGE_HASHER = MessageHasher(config=PROD_CONFIG, poseidon=PROD_POSEIDON)
"""An instance configured for production-level parameters."""

TEST_MESSAGE_HASHER = MessageHasher(config=TEST_CONFIG, poseidon=TEST_POSEIDON)
"""A lightweight instance for test environments."""
