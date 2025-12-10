"""
Defines the cryptographic constants and configuration presets for the
XMSS spec.

This specification corresponds to the "hashing-optimized" Top Level Target Sum
instantiation from the canonical Rust implementation
(production instantiation).

We also provide a test instantiation for testing purposes.
"""

from typing_extensions import Final

from lean_spec.types import StrictBaseModel, Uint64

from ..koalabear import P_BYTES, Fp


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
        The maximum number of epochs supported by this configuration.

        An individual key pair can be active for a smaller sub-range.
        """
        return Uint64(1 << self.LOG_LIFETIME)

    DIMENSION: int
    """The total number of hash chains, `v`."""

    BASE: int
    """The alphabet size for the digits of the encoded message."""

    FINAL_LAYER: int
    """Number of top layers of the hypercube to map the hash output into."""

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
    """The capacity of the Poseidon2 sponge, defining its security level."""

    POS_OUTPUT_LEN_PER_INV_FE: int
    """Output length per invocation for the message hash."""

    POS_INVOCATIONS: int
    """Number of invocations for the message hash."""

    @property
    def POS_OUTPUT_LEN_FE(self) -> int:  # noqa: N802
        """Total output length for the message hash."""
        return self.POS_OUTPUT_LEN_PER_INV_FE * self.POS_INVOCATIONS

    @property
    def PUBLIC_KEY_LEN_BYTES(self) -> int:  # noqa: N802
        """The size of the public key in bytes."""
        return self.HASH_LEN_FE * P_BYTES + self.PARAMETER_LEN * P_BYTES

    @property
    def SIGNATURE_LEN_BYTES(self) -> int:  # noqa: N802
        """The size of the signature in bytes."""
        # - path siblings: LOG_LIFETIME siblings × HASH_LEN_FE elements
        # - rho: RAND_LEN_FE elements
        # - hashes: DIMENSION hashes × HASH_LEN_FE elements per hash
        path_size = self.LOG_LIFETIME * self.HASH_LEN_FE * P_BYTES
        rho_size = self.RAND_LEN_FE * P_BYTES
        hashes_size = self.DIMENSION * self.HASH_LEN_FE * P_BYTES
        return path_size + rho_size + hashes_size


PROD_CONFIG: Final = XmssConfig(
    MESSAGE_LENGTH=32,
    LOG_LIFETIME=32,
    DIMENSION=64,
    BASE=8,
    FINAL_LAYER=77,
    TARGET_SUM=375,
    MAX_TRIES=100_000,
    PARAMETER_LEN=5,
    TWEAK_LEN_FE=2,
    MSG_LEN_FE=9,
    RAND_LEN_FE=7,
    HASH_LEN_FE=8,
    CAPACITY=9,
    POS_OUTPUT_LEN_PER_INV_FE=15,
    POS_INVOCATIONS=1,
)


TEST_CONFIG: Final = XmssConfig(
    MESSAGE_LENGTH=32,
    LOG_LIFETIME=8,
    DIMENSION=4,
    BASE=4,
    FINAL_LAYER=6,
    TARGET_SUM=6,
    MAX_TRIES=100_000,
    PARAMETER_LEN=5,
    TWEAK_LEN_FE=2,
    MSG_LEN_FE=9,
    RAND_LEN_FE=7,
    HASH_LEN_FE=8,
    CAPACITY=9,
    POS_OUTPUT_LEN_PER_INV_FE=15,
    POS_INVOCATIONS=1,
)


TWEAK_PREFIX_CHAIN: Final = Fp(value=0x00)
"""The unique prefix for tweaks used in Winternitz-style hash chains."""

TWEAK_PREFIX_TREE: Final = Fp(value=0x01)
"""The unique prefix for tweaks used when hashing Merkle tree nodes."""

TWEAK_PREFIX_MESSAGE: Final = Fp(value=0x02)
"""The unique prefix for tweaks used in the initial message hashing step."""

PRF_KEY_LENGTH: int = 32
"""The length of the PRF secret key in bytes."""

lean_env_to_config = {
    "test": TEST_CONFIG,
    "prod": PROD_CONFIG,
}

# Select active configuration based on LEAN_ENV environment variable
import os

LEAN_ENV = os.environ.get("LEAN_ENV", "prod").lower()
"""The active signature scheme name ('prod' or 'test')."""

if lean_env_to_config.get(LEAN_ENV) is None:
    raise ValueError(
        f"Invalid LEAN_ENV environment variable: '{LEAN_ENV}'. "
        f"Available schemes: {configs.keys()}"
    )

ENV_CONFIG: Final = lean_env_to_config[LEAN_ENV]
"""The active XMSS configuration based on LEAN_ENV environment variable."""
