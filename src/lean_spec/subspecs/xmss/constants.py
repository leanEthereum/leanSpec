"""
Defines the cryptographic constants for the XMSS specification.

This specification corresponds to the "hashing-optimized" Top Level Target Sum
instantiation from the canonical Rust implementation.

.. note::
   This specification uses the **KoalaBear** prime field, which is consistent
   with the formal analysis in the reference papers (e.g., Section 5 of the
   "LeanSig" technical note: https://eprint.iacr.org/2025/1332).

   The canonical Rust implementation currently uses the `BabyBear` field for
   practical reasons but is expected to align with this
   specification in the future.
"""

from ..koalabear import Fp

# =================================================================
# Core Scheme Configuration
# =================================================================

MESSAGE_LENGTH: int = 32
"""The length in bytes for all messages to be signed."""

LOG_LIFETIME: int = 32
"""The base-2 logarithm of the scheme's maximum lifetime."""

LIFETIME: int = 1 << LOG_LIFETIME
"""
The maximum number of epochs supported by this configuration.

An individual key pair can be active for a smaller sub-range.
"""


# =================================================================
# Target Sum WOTS Parameters
# =================================================================

DIMENSION: int = 64
"""The total number of hash chains, `v`."""

BASE: int = 8
"""The alphabet size for the digits of the encoded message."""

FINAL_LAYER: int = 77
"""The number of top layers of the hypercube to map the hash output into."""

TARGET_SUM: int = 375
"""The required sum of all codeword chunks for a signature to be valid."""


# =================================================================
# Hash and Encoding Length Parameters (in field elements)
# =================================================================

PARAMETER_LEN: int = 5
"""
The length of the public parameter `P`.

It is used to specialize the hash function.
"""

TWEAK_LEN_FE: int = 2
"""The length of a domain-separating tweak."""

MSG_LEN_FE: int = 9
"""The length of a message after being encoded into field elements."""

RAND_LEN_FE: int = 7
"""The length of the randomness `rho` used during message encoding."""

HASH_LEN_FE: int = 8
"""The output length of the main tweakable hash function."""

CAPACITY: int = 9
"""The capacity of the Poseidon2 sponge, defining its security level."""

POS_OUTPUT_LEN_PER_INV_FE: int = 15
"""Output length per invocation for the message hash."""

POS_INVOCATIONS: int = 1
"""Number of invocations for the message hash."""

POS_OUTPUT_LEN_FE: int = POS_OUTPUT_LEN_PER_INV_FE * POS_INVOCATIONS
"""Total output length for the message hash."""


# =================================================================
# Domain Separator Prefixes for Tweaks
# =================================================================

TWEAK_PREFIX_CHAIN = Fp(value=0x00)
"""The unique prefix for tweaks used in Winternitz-style hash chains."""

TWEAK_PREFIX_TREE = Fp(value=0x01)
"""The unique prefix for tweaks used when hashing Merkle tree nodes."""

TWEAK_PREFIX_MESSAGE = Fp(value=0x02)
"""The unique prefix for tweaks used in the initial message hashing step."""
