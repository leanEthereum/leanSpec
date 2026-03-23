"""
Defines the cryptographic constants and configuration presets for the
XMSS spec.

This specification corresponds to the "hashing-optimized" Top Level Target Sum
instantiation from the canonical Rust implementation
(production instantiation).

We also provide a test instantiation for testing purposes.
"""

from __future__ import annotations

import math
from typing import Final

from pydantic import model_validator

from lean_spec.config import LEAN_ENV
from lean_spec.types import StrictBaseModel, Uint64
from lean_spec.types.constants import OFFSET_BYTE_LENGTH

from ..koalabear import P_BYTES, Fp, P


class XmssConfig(StrictBaseModel):
    """A model holding the configuration constants for an XMSS preset."""

    # --- Core Scheme Configuration ---
    MESSAGE_LENGTH: int
    """The length in bytes for all messages to be signed."""

    LOG_LIFETIME: int
    """The base-2 logarithm of the scheme's maximum lifetime."""

    @property
    def LIFETIME(self) -> Uint64:  # noqa: N802
        """
        The maximum number of slots supported by this configuration.

        An individual key pair can be active for a smaller sub-range.
        """
        return Uint64(1 << self.LOG_LIFETIME)

    DIMENSION: int
    """The total number of hash chains, `v`."""

    BASE: int
    """The alphabet size for the digits of the encoded message."""

    Z: int
    """Number of base-`BASE` digits extracted from each field element."""

    Q: int
    """Quotient such that `Q * BASE^Z == P - 1`."""

    TARGET_SUM: int
    """The required sum of all codeword chunks for a signature to be valid."""

    MAX_TRIES: int
    """
    How often one should try at most to resample a random value.

    This is currently based on experiments with the Rust implementation.
    Should probably be modified in production.
    """

    PARAMETER_LEN: int
    """
    The length of the public parameter `P`.

    It is used to specialize the hash function.
    """

    TWEAK_LEN_FE: int
    """The length of a domain-separating tweak."""

    MSG_LEN_FE: int
    """The length of a message after being encoded into field elements."""

    RAND_LEN_FE: int
    """The length of the randomness `rho` used during message encoding."""

    HASH_LEN_FE: int
    """The output length of the main tweakable hash function."""

    CAPACITY: int
    """The capacity of the Poseidon1 sponge, defining its security level."""

    @model_validator(mode="after")
    def _validate_decomposition(self) -> XmssConfig:
        """Verify that Q * BASE^Z == P - 1."""
        if self.Q * self.BASE**self.Z != P - 1:
            raise ValueError(f"Q * BASE^Z must equal P-1={P - 1}")
        return self

    @property
    def MH_HASH_LEN_FE(self) -> int:  # noqa: N802
        """Number of Poseidon output field elements needed for the aborting decode."""
        return math.ceil(self.DIMENSION / self.Z)

    @property
    def PUBLIC_KEY_LEN_BYTES(self) -> int:  # noqa: N802
        """The size of the public key in bytes."""
        return self.HASH_LEN_FE * P_BYTES + self.PARAMETER_LEN * P_BYTES

    @property
    def SIGNATURE_LEN_BYTES(self) -> int:  # noqa: N802
        """
        The SSZ-encoded size of a signature in bytes.

        Includes raw field data plus SSZ offset overhead for variable-size fields:

        - Signature container: 2 offsets (path, hashes)
        - HashTreeOpening container: 1 offset (siblings)
        """
        # Raw data sizes
        path_siblings_size = self.LOG_LIFETIME * self.HASH_LEN_FE * P_BYTES
        rho_size = self.RAND_LEN_FE * P_BYTES
        hashes_size = self.DIMENSION * self.HASH_LEN_FE * P_BYTES

        # SSZ offset overhead: 3 variable fields × 4 bytes each
        ssz_offset_overhead = 3 * OFFSET_BYTE_LENGTH

        return path_siblings_size + rho_size + hashes_size + ssz_offset_overhead


PROD_CONFIG: Final = XmssConfig(
    MESSAGE_LENGTH=32,
    LOG_LIFETIME=32,
    DIMENSION=46,
    BASE=8,
    Z=8,
    Q=127,
    TARGET_SUM=200,
    MAX_TRIES=100_000,
    PARAMETER_LEN=5,
    TWEAK_LEN_FE=2,
    MSG_LEN_FE=9,
    RAND_LEN_FE=7,
    HASH_LEN_FE=8,
    CAPACITY=9,
)


TEST_CONFIG: Final = XmssConfig(
    MESSAGE_LENGTH=32,
    LOG_LIFETIME=8,
    DIMENSION=4,
    BASE=4,
    Z=2,
    Q=133169152,
    TARGET_SUM=6,
    MAX_TRIES=100_000,
    PARAMETER_LEN=5,
    TWEAK_LEN_FE=2,
    MSG_LEN_FE=9,
    RAND_LEN_FE=7,
    HASH_LEN_FE=8,
    CAPACITY=9,
)


TWEAK_PREFIX_CHAIN: Final = Fp(value=0x00)
"""The unique prefix for tweaks used in Winternitz-style hash chains."""

TWEAK_PREFIX_TREE: Final = Fp(value=0x01)
"""The unique prefix for tweaks used when hashing Merkle tree nodes."""

TWEAK_PREFIX_MESSAGE: Final = Fp(value=0x02)
"""The unique prefix for tweaks used in the initial message hashing step."""

PRF_KEY_LENGTH: Final = 32
"""The length of the PRF secret key in bytes."""

_LEAN_ENV_TO_CONFIG = {
    "test": TEST_CONFIG,
    "prod": PROD_CONFIG,
}

TARGET_CONFIG: Final = _LEAN_ENV_TO_CONFIG[LEAN_ENV]
"""The active XMSS configuration based on LEAN_ENV environment variable."""
