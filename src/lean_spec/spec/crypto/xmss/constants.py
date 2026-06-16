"""Cryptographic constants and configuration presets for the XMSS spec."""

import math
from typing import Final, Self

from pydantic import model_validator

from lean_spec.base import StrictBaseModel
from lean_spec.config import LEAN_ENV
from lean_spec.spec.crypto.koalabear import P_BYTES, P
from lean_spec.spec.ssz import Uint64
from lean_spec.spec.ssz.ssz_base import BYTES_PER_LENGTH_OFFSET


class XmssConfig(StrictBaseModel):
    """A model holding the configuration constants for an XMSS preset."""

    LOG_LIFETIME: int
    """The base-2 logarithm of the scheme's maximum lifetime."""

    DIMENSION: int
    """The total number of hash chains, v."""

    BASE: int
    """The alphabet size for the digits of the encoded message."""

    Z: int
    """Number of base-BASE digits extracted from each field element."""

    Q: int
    """Quotient such that Q * BASE^Z == P - 1."""

    TARGET_SUM: int
    """The required sum of all codeword chunks for a signature to be valid."""

    MAX_TRIES: int
    """How often one should try at most to resample a random value."""

    PARAMETER_LENGTH: int
    """The length of the public parameter P.

    It is used to specialize the hash function."""

    TWEAK_LENGTH_FIELD_ELEMENTS: int
    """The length of a domain-separating tweak."""

    MESSAGE_LENGTH_FIELD_ELEMENTS: int
    """The length of a message after being encoded into field elements."""

    RAND_LENGTH_FIELD_ELEMENTS: int
    """The length of the randomness rho used during message encoding."""

    HASH_LENGTH_FIELD_ELEMENTS: int
    """The output length of the main tweakable hash function."""

    CAPACITY: int
    """The capacity of the Poseidon sponge, defining its security level."""

    @model_validator(mode="after")
    def _validate_decomposition(self) -> Self:
        """Verify that Q * BASE^Z == P - 1."""
        if self.Q * self.BASE**self.Z != P - 1:
            raise ValueError(f"Q * BASE^Z must equal P-1={P - 1}")
        return self

    @property
    def LIFETIME(self) -> Uint64:
        """
        The maximum number of slots supported by this configuration.

        An individual key pair can be active for a smaller sub-range.
        """
        return Uint64(1 << self.LOG_LIFETIME)

    @property
    def LEAVES_PER_BOTTOM_TREE(self) -> int:
        """Slots covered by one bottom tree, W = sqrt(LIFETIME) = 2^(LOG_LIFETIME / 2)."""
        return 1 << (self.LOG_LIFETIME // 2)

    @property
    def MH_HASH_LENGTH_FIELD_ELEMENTS(self) -> int:
        """Number of Poseidon output field elements needed for the aborting decode."""
        return math.ceil(self.DIMENSION / self.Z)

    @property
    def SIGNATURE_LENGTH_BYTES(self) -> int:
        """
        The SSZ-encoded size of a signature in bytes.

        # Layout

            authentication path : one sibling digest per tree level   (variable)
            encoding randomness : fixed run of field elements         (fixed)
            released chain ends : one digest per hash chain           (variable)
        """
        # One sibling digest per level climbed from leaf to root.
        path_siblings_size = self.LOG_LIFETIME * self.HASH_LENGTH_FIELD_ELEMENTS * P_BYTES
        rho_size = self.RAND_LENGTH_FIELD_ELEMENTS * P_BYTES
        # One released chain end per chain, so the count is the scheme dimension.
        hashes_size = self.DIMENSION * self.HASH_LENGTH_FIELD_ELEMENTS * P_BYTES

        # SSZ writes a four-byte offset ahead of each variable-length field.
        #
        #     path        -> offset 1   (top level)
        #     chain ends  -> offset 2   (top level)
        #     siblings    -> offset 3   (nested inside the path)
        #
        # The randomness is fixed-length, so it carries no offset.
        ssz_offset_overhead = 3 * BYTES_PER_LENGTH_OFFSET

        return path_siblings_size + rho_size + hashes_size + ssz_offset_overhead


PROD_CONFIG: Final = XmssConfig(
    LOG_LIFETIME=32,
    DIMENSION=46,
    BASE=8,
    Z=8,
    Q=127,
    TARGET_SUM=200,
    MAX_TRIES=100_000,
    PARAMETER_LENGTH=5,
    TWEAK_LENGTH_FIELD_ELEMENTS=2,
    MESSAGE_LENGTH_FIELD_ELEMENTS=9,
    RAND_LENGTH_FIELD_ELEMENTS=7,
    HASH_LENGTH_FIELD_ELEMENTS=8,
    CAPACITY=9,
)
"""Production XMSS configuration matching the canonical Rust instantiation."""


TEST_CONFIG: Final = XmssConfig(
    LOG_LIFETIME=8,
    DIMENSION=4,
    BASE=8,
    Z=8,
    Q=127,
    TARGET_SUM=6,
    MAX_TRIES=100_000,
    PARAMETER_LENGTH=5,
    TWEAK_LENGTH_FIELD_ELEMENTS=2,
    MESSAGE_LENGTH_FIELD_ELEMENTS=9,
    RAND_LENGTH_FIELD_ELEMENTS=7,
    HASH_LENGTH_FIELD_ELEMENTS=8,
    CAPACITY=9,
)
"""Lightweight XMSS configuration for fast test execution."""


TWEAK_PREFIX_CHAIN: Final[int] = 0x00
"""The unique prefix for tweaks used in Winternitz-style hash chains."""

TWEAK_PREFIX_TREE: Final[int] = 0x01
"""The unique prefix for tweaks used when hashing Merkle tree nodes."""

TWEAK_PREFIX_MESSAGE: Final[int] = 0x02
"""The unique prefix for tweaks used in the initial message hashing step."""

PRF_KEY_LENGTH: Final = 32
"""The length of the PRF secret key in bytes."""

TARGET_CONFIG: Final = TEST_CONFIG if LEAN_ENV == "test" else PROD_CONFIG
"""Active configuration selected at import time from the LEAN_ENV environment variable."""
