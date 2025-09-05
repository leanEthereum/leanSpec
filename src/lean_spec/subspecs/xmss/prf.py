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
from lean_spec.types.uint64 import Uint64

from .constants import (
    PRF_KEY_LENGTH,
    PROD_CONFIG,
    TEST_CONFIG,
    XmssConfig,
)
from .containers import PRFKey

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
        Applies the PRF to derive the secret starting value for a single hash chain.

        ### PRF Construction

        The function constructs a unique input for the underlying SHAKE128 function
        by concatenating several components:
        `SHAKE128(DOMAIN_SEP || key || epoch || chain_index)`

        The arbitrary-length output of SHAKE128 is then processed to produce a
        list of field elements, which serves as the secret starting digest for one chain.

        Args:
            key: The secret master PRF key.
            epoch: The epoch number, identifying the one-time signature instance.
            chain_index: The index of the hash chain within that epoch's OTS.

        Returns:
            A list of field elements representing the secret start of a single
            hash chain (i.e., a `HashDigest`).
        """
        # Retrieve the scheme's configuration parameters.
        config = self.config

        # Construct the unique input for the PRF by concatenating its components:
        #
        # - Domain Separation: Uniquely tag the PRF for this specific use case.
        # - Key Input: The master secret key.
        # - Epoch: A 4-byte integer ensuring every epoch derives a different set of secrets.
        # - Chain Index: An 8-byte integer ensuring each parallel hash chain gets a unique secret.
        input_data = (
            PRF_DOMAIN_SEP + key + epoch.to_bytes(4, "big") + chain_index.to_bytes(8, "big")
        )

        # Determine the total number of bytes to extract from the SHAKE output.
        #
        # We need enough bytes to produce `HASH_LEN_FE` field elements.
        num_bytes_to_read = PRF_BYTES_PER_FE * config.HASH_LEN_FE
        prf_output_bytes = hashlib.shake_128(input_data).digest(num_bytes_to_read)

        # Convert the raw byte output into a list of field elements.
        #
        # For each required field element, this performs the following steps:
        # - Slice an 8-byte (64-bit) chunk from the `prf_output_bytes`.
        # - Convert that chunk from a big-endian byte representation to an integer.
        # - Create a field element from the integer (the Fp constructor handles the modulo).
        return [
            Fp(
                value=int.from_bytes(
                    prf_output_bytes[i * PRF_BYTES_PER_FE : (i + 1) * PRF_BYTES_PER_FE],
                    "big",
                )
            )
            for i in range(config.HASH_LEN_FE)
        ]


PROD_PRF = Prf(PROD_CONFIG)
"""An instance configured for production-level parameters."""

TEST_PRF = Prf(TEST_CONFIG)
"""A lightweight instance for test environments."""
