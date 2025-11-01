"""
Defines the cryptographic constants and configuration presets for the
XMSS spec.

This specification corresponds to the "hashing-optimized" Top Level Target Sum
instantiation from the canonical Rust implementation
(production instantiation).

We also provide a test instantiation for testing purposes.
"""

from typing_extensions import Final

from lean_spec.types import StrictBaseModel

from ..koalabear import Fp


class XmssConfig(StrictBaseModel):
    """A model holding the configuration constants for an XMSS preset."""

    # --- Core Scheme Configuration ---
    MESSAGE_LENGTH: int
    """The length in bytes for all messages to be signed."""

    LOG_LIFETIME: int
    """The base-2 logarithm of the scheme's maximum lifetime."""

    @property
    def LIFETIME(self) -> int:  # noqa: N802
        """
        The maximum number of epochs supported by this configuration.

        An individual key pair can be active for a smaller sub-range.
        """
        return 1 << self.LOG_LIFETIME

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
    DIMENSION=16,
    BASE=4,
    FINAL_LAYER=24,
    TARGET_SUM=24,
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

# Public key and signature sizes for the production and test configurations

FE_SIZE_BYTES: int = 4
"""Size of a single field element in bytes."""

# 52 bytes
PROD_PUBKEY_SIZE_BYTES = (PROD_CONFIG.HASH_LEN_FE + PROD_CONFIG.PARAMETER_LEN) * FE_SIZE_BYTES
"""Size in bytes of the production public key representation."""

# 52 bytes
TEST_PUBKEY_SIZE_BYTES = (TEST_CONFIG.HASH_LEN_FE + TEST_CONFIG.PARAMETER_LEN) * FE_SIZE_BYTES
"""Size in bytes of the test public key representation."""

PROD_SIGNATURE_SIZE_BYTES = (
    PROD_CONFIG.LOG_LIFETIME * PROD_CONFIG.HASH_LEN_FE * FE_SIZE_BYTES
    + PROD_CONFIG.RAND_LEN_FE * FE_SIZE_BYTES
    + PROD_CONFIG.DIMENSION * PROD_CONFIG.HASH_LEN_FE * FE_SIZE_BYTES
)  # 3100 bytes
"""Total size in bytes of a production signature, including all components."""

TEST_SIGNATURE_SIZE_BYTES = (
    TEST_CONFIG.LOG_LIFETIME * TEST_CONFIG.HASH_LEN_FE * FE_SIZE_BYTES
    + TEST_CONFIG.RAND_LEN_FE * FE_SIZE_BYTES
    + TEST_CONFIG.DIMENSION * TEST_CONFIG.HASH_LEN_FE * FE_SIZE_BYTES
)  # 796 bytes
"""Total size in bytes of a test signature, including all components."""

PUBKEY_SIZE_BYTES = max(PROD_PUBKEY_SIZE_BYTES, TEST_PUBKEY_SIZE_BYTES)  # 52 bytes
"""Maximum public key size across all XMSS presets."""

SIGNATURE_SIZE_BYTES = max(PROD_SIGNATURE_SIZE_BYTES, TEST_SIGNATURE_SIZE_BYTES)  # 3100 bytes
"""Maximum signature size across all XMSS presets."""

PUBKEY_PADDING_LENGTH = abs(PROD_PUBKEY_SIZE_BYTES - TEST_PUBKEY_SIZE_BYTES)  # 0 bytes
"""Padding required to align public key sizes between presets."""

SIGNATURE_PADDING_LENGTH = abs(PROD_SIGNATURE_SIZE_BYTES - TEST_SIGNATURE_SIZE_BYTES)  # 2304 bytes
"""Padding required to align signature sizes between presets."""
