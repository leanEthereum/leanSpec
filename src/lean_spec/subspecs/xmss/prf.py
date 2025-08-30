"""
Defines the pseudorandom function (PRF) used in the signature scheme.

PRF based on the SHAKE128 extendable-output function (XOF).

The PRF is used to derive the secret starting points of the hash chains
for each epoch from a single master secret key.
"""

from __future__ import annotations

import hashlib
import os
from typing import List

from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss.constants import (
    PRF_KEY_LENGTH,
    PROD_CONFIG,
    TEST_CONFIG,
    XmssConfig,
)
from lean_spec.subspecs.xmss.structures import PRFKey
from lean_spec.types.uint64 import Uint64

PRF_DOMAIN_SEP: bytes = bytes(
    [
        0xAE,
        0xAE,
        0x22,
        0xFF,
        0x00,
        0x01,
        0xFA,
        0xFF,
        0x21,
        0xAF,
        0x12,
        0x00,
        0x01,
        0x11,
        0xFF,
        0x00,
    ]
)
"""
A 16-byte domain separator to ensure PRF outputs are unique to this context.

This prevents any potential conflicts if the same underlying hash function
(SHAKE128) were used for other purposes in the system.
"""

PRF_BYTES_PER_FE: int = 8
"""
The number of bytes of SHAKE128 output used to generate one field element.

We use 8 bytes (64 bits) of pseudorandom output, which is then reduced
modulo the 31-bit field prime `P`. This provides a significant statistical
safety margin to ensure the resulting field element is close to uniformly
random.
"""


class Prf:
    """An instance of the SHAKE128-based PRF for a given config."""

    def __init__(self, config: XmssConfig):
        """Initializes the PRF with a specific parameter set."""
        self.config = config

    def key_gen(self) -> PRFKey:
        """
        Generates a cryptographically secure random key for the PRF.

        This function sources randomness from the operating system's
        entropy pool.

        Returns:
            A new, randomly generated PRF key of `PRF_KEY_LENGTH` bytes.
        """
        return os.urandom(PRF_KEY_LENGTH)

    def apply(self, key: PRFKey, epoch: int, chain_index: Uint64) -> List[Fp]:
        """
        Applies the PRF to derive the secret values for a specific epoch
        and chain.

        The function computes:
        `SHAKE128(DOMAIN_SEP || key || epoch || chain_index)`
        and interprets the output as a list of field elements.

        Args:
            key: The secret PRF key.
            epoch: The epoch number (a 32-bit unsigned integer).
            chain_index: The index of the hash chain (a 64-bit uint).

        Returns:
            A list of `DIMENSION` field elements, which are the secret starting
            points for the hash chains of the specified epoch.
        """
        # Get the config for this scheme.
        config = self.config

        # Create a new SHAKE128 hash instance.
        hasher = hashlib.shake_128()

        # Absorb the domain separator to contextualize the hash.
        hasher.update(PRF_DOMAIN_SEP)

        # Absorb the secret key.
        hasher.update(key)

        # Absorb the epoch, represented as a 4-byte big-endian integer.
        #
        # This ensures that each epoch produces a unique set of secrets.
        hasher.update(epoch.to_bytes(4, "big"))

        # Absorb the chain index, as an 8-byte big-endian integer.
        #
        # This is used to derive a unique start value for each hash chain.
        hasher.update(chain_index.to_bytes(8, "big"))

        # Determine the total number of bytes to extract from the SHAKE output.
        #
        # For key generation, we need one field element per chain.
        num_bytes_to_read = PRF_BYTES_PER_FE * config.HASH_LEN_FE
        prf_output_bytes = hasher.digest(num_bytes_to_read)

        # Convert the byte output into a list of field elements.
        output_elements: List[Fp] = []
        for i in range(config.HASH_LEN_FE):
            # Extract an 8-byte chunk for the current field element.
            start = i * PRF_BYTES_PER_FE
            end = start + PRF_BYTES_PER_FE
            chunk = prf_output_bytes[start:end]

            # Convert the chunk to a large integer.
            integer_value = int.from_bytes(chunk, "big")

            # Reduce the integer modulo the field prime `P`.
            #
            # The Fp constructor handles the modulo operation automatically.
            output_elements.append(Fp(value=integer_value))

        return output_elements


PROD_PRF = Prf(PROD_CONFIG)
"""An instance configured for production-level parameters."""

TEST_PRF = Prf(TEST_CONFIG)
"""A lightweight instance for test environments."""
