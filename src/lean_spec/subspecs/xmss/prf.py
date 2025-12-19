"""
Defines the pseudorandom function (PRF) used in the signature scheme.

PRF based on the SHAKE128 extendable-output function (XOF).

The PRF is used to derive the secret starting points of the hash chains
for each epoch from a single master secret key.
"""

from __future__ import annotations

import hashlib
import os

from pydantic import model_validator

from lean_spec.subspecs.koalabear import Fp
from lean_spec.types import StrictBaseModel, Uint64

from .constants import (
    PRF_KEY_LENGTH,
    PROD_CONFIG,
    TEST_CONFIG,
    XmssConfig,
)
from .types import HashDigestVector, PRFKey, Randomness

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

PRF_DOMAIN_SEP_DOMAIN_ELEMENT: bytes = bytes([0x00])
"""
A 1-byte domain separator for deriving domain elements (used in `apply`).

This distinguishes the PRF calls for generating hash chain starting points
from the PRF calls for generating randomness during signing.
"""

PRF_DOMAIN_SEP_RANDOMNESS: bytes = bytes([0x01])
"""
A 1-byte domain separator for deriving randomness (used in `get_randomness`).

This distinguishes the PRF calls for generating signing randomness from the
PRF calls for generating domain elements, preventing any potential collisions
between the two use cases.
"""

PRF_BYTES_PER_FE: int = 8
"""
The number of bytes of SHAKE128 output used to generate one field element.

We use 8 bytes (64 bits) of pseudorandom output, which is then reduced
modulo the 31-bit field prime `P`. This provides a significant statistical
safety margin to ensure the resulting field element is close to uniformly
random.
"""


def _bytes_to_field_elements(data: bytes, count: int) -> list[Fp]:
    """
    Convert PRF output bytes into a list of field elements.

    Each field element is derived from `PRF_BYTES_PER_FE` bytes,
    interpreted as a big-endian integer and reduced modulo the field prime.

    The extra bits provide statistical uniformity.

    Args:
        data: Raw bytes from SHAKE128 output. Must be exactly `count * PRF_BYTES_PER_FE` bytes.
        count: Number of field elements to extract.

    Returns:
        List of `count` field elements.
    """
    return [
        Fp(value=int.from_bytes(data[i : i + PRF_BYTES_PER_FE], "big"))
        for i in range(0, count * PRF_BYTES_PER_FE, PRF_BYTES_PER_FE)
    ]


class Prf(StrictBaseModel):
    """An instance of the SHAKE128-based PRF for a given config."""

    config: XmssConfig
    """Configuration parameters for the PRF."""

    @model_validator(mode="after")
    def enforce_strict_types(self) -> "Prf":
        """Reject subclasses to prevent type confusion attacks."""
        if type(self.config) is not XmssConfig:
            raise TypeError("config must be exactly XmssConfig, not a subclass")
        return self

    def key_gen(self) -> PRFKey:
        """
        Generates a cryptographically secure random key for the PRF.

        This function sources randomness from the operating system's
        entropy pool.

        Returns:
            A new, randomly generated PRF key of `PRF_KEY_LENGTH` bytes.
        """
        return PRFKey(os.urandom(PRF_KEY_LENGTH))

    def apply(self, key: PRFKey, epoch: Uint64, chain_index: Uint64) -> HashDigestVector:
        """
        Applies the PRF to derive the secret starting value for a single hash chain.

        ### PRF Construction

        The function constructs a unique input for the underlying SHAKE128 function
        by concatenating several components:
        `SHAKE128(DOMAIN_SEP || 0x00 || key || epoch || chain_index)`

        The 0x00 byte distinguishes this use case (deriving domain elements) from
        randomness generation (which uses 0x01). The arbitrary-length output of
        SHAKE128 is then processed to produce a list of field elements, which
        serves as the secret starting digest for one chain.

        Args:
            key: The secret master PRF key.
            epoch: The epoch number, identifying the one-time signature instance.
            chain_index: The index of the hash chain within that epoch's OTS.

        Returns:
            A hash digest representing the secret start of a single hash chain.
        """
        # Retrieve the scheme's configuration parameters.
        config = self.config

        # Construct the unique input for the PRF by concatenating its components:
        #
        # - Domain Separation: Uniquely tag the PRF for this specific use case.
        # - Domain Element Tag: 0x00 byte to distinguish from randomness generation.
        # - Key Input: The master secret key.
        # - Epoch: A 4-byte integer ensuring every epoch derives a different set of secrets.
        # - Chain Index: An 8-byte integer ensuring each parallel hash chain gets a unique secret.
        input_data = (
            PRF_DOMAIN_SEP
            + PRF_DOMAIN_SEP_DOMAIN_ELEMENT
            + key
            + int(epoch).to_bytes(4, "big")
            + chain_index.to_bytes(8, "big")
        )

        # Determine the total number of bytes to extract from the SHAKE output.
        #
        # We need enough bytes to produce `HASH_LEN_FE` field elements.
        num_bytes_to_read = PRF_BYTES_PER_FE * config.HASH_LEN_FE
        prf_output_bytes = hashlib.shake_128(input_data).digest(num_bytes_to_read)

        # Convert the raw byte output into a list of field elements.
        return HashDigestVector(data=_bytes_to_field_elements(prf_output_bytes, config.HASH_LEN_FE))

    def get_randomness(
        self, key: PRFKey, epoch: Uint64, message: bytes, counter: Uint64
    ) -> Randomness:
        """
        Derives pseudorandom field elements for use in deterministic signing.

        This method is used to generate deterministic randomness for the Information
        Encoding step during signing. By deriving randomness from the PRF key, epoch,
        message, and attempt counter, we ensure that signing is deterministic: calling
        `sign` twice with the same (sk, epoch, message) triple produces the same signature.

        This provides additional hardening against implementation errors where sign might
        be called multiple times with the same epoch. However, calling sign with the same
        epoch but *different* messages still compromises security.

        ### Construction

        Similar to `apply`, but includes the message and a counter in the input:
        `SHAKE128(DOMAIN_SEP || 0x01 || key || epoch || message || counter)`

        The 0x01 byte distinguishes this use case (generating randomness) from
        domain element derivation (which uses 0x00).

        Args:
            key: The secret master PRF key.
            epoch: The epoch number for this signature.
            message: The message being signed (MESSAGE_LENGTH bytes).
            counter: The attempt number (used when retrying encoding).

        Returns:
            Randomness for encoding (i.e., `rho`).
        """
        config = self.config

        # Validate message length
        if len(message) != config.MESSAGE_LENGTH:
            raise ValueError(
                f"Message must be exactly {config.MESSAGE_LENGTH} bytes, got {len(message)}"
            )

        # Construct input: DOMAIN_SEP || 0x01 || key || epoch || message || counter
        input_data = (
            PRF_DOMAIN_SEP
            + PRF_DOMAIN_SEP_RANDOMNESS
            + key
            + int(epoch).to_bytes(4, "big")
            + message
            + int(counter).to_bytes(8, "big")
        )

        # Extract enough bytes for RAND_LEN_FE field elements
        num_bytes_to_read = PRF_BYTES_PER_FE * config.RAND_LEN_FE
        prf_output_bytes = hashlib.shake_128(input_data).digest(num_bytes_to_read)

        # Convert to field elements and wrap in Randomness
        return Randomness(data=_bytes_to_field_elements(prf_output_bytes, config.RAND_LEN_FE))


PROD_PRF = Prf(config=PROD_CONFIG)
"""An instance configured for production-level parameters."""

TEST_PRF = Prf(config=TEST_CONFIG)
"""A lightweight instance for test environments."""
