"""SHAKE128-based pseudorandom function for deterministic key derivation."""

import hashlib
import os
from itertools import batched
from typing import Final, Self

from lean_spec.spec.ssz import Bytes16, Bytes32, Uint64
from lean_spec.spec.ssz.byte_arrays import BaseBytes

from ..koalabear import Fp
from .constants import PRF_KEY_LENGTH, XmssConfig
from .types import HashDigestVector, Randomness

PRF_DOMAIN_SEP: Final = Bytes16(b"\xae\xae\x22\xff\x00\x01\xfa\xff\x21\xaf\x12\x00\x01\x11\xff\x00")
"""
Fixed domain separator prefixed to every PRF call.

Prevents cross-context collisions if SHAKE128 is reused elsewhere in the system.
"""

PRF_DOMAIN_SEP_DOMAIN_ELEMENT: Final[bytes] = b"\x00"
"""Subdomain tag for hash-chain start derivation."""

PRF_DOMAIN_SEP_RANDOMNESS: Final[bytes] = b"\x01"
"""Subdomain tag for signing-randomness derivation."""

PRF_BYTES_PER_FE: Final[int] = 16
"""
SHAKE128 bytes consumed per output field element.

128 bits reduced modulo a 31-bit prime gives a statistical margin against bias.
"""


class PRFKey(BaseBytes):
    """
    The PRF master secret key.

    High-entropy byte string acting as the single root secret.

    Every one-time signing key is deterministically derived from this seed.
    """

    LENGTH = PRF_KEY_LENGTH

    @classmethod
    def generate(cls) -> Self:
        """Draw a fresh master key from the operating system entropy pool."""
        return cls(os.urandom(PRF_KEY_LENGTH))

    def derive_chain_start(
        self, config: XmssConfig, epoch: Uint64, chain_index: Uint64
    ) -> HashDigestVector:
        """
        Derive the secret start of one Winternitz hash chain.

        # Overview

        Each slot signs with many independent hash chains.
        A chain begins at a secret value.
        Its public counterpart is that value hashed all the way up to the chain top.
        Recreating the secret start from the seed means it never has to be stored.

        Args:
            config: Active XMSS configuration.
            epoch: Slot identifier for this one-time signature instance.
            chain_index: Position of the chain within the one-time signature.

        Returns:
            The secret digest at the bottom of the chain.
        """
        # Layout:
        #
        #     domain_sep || 0x00 || key || epoch (4 bytes) || chain_index (8 bytes)
        #
        # The 0x00 byte separates chain-start derivation from randomness derivation.
        input_data = (
            PRF_DOMAIN_SEP
            + PRF_DOMAIN_SEP_DOMAIN_ELEMENT
            + self
            + epoch.to_bytes(4, "big")
            + chain_index.to_bytes(8, "big")
        )

        # Pull enough SHAKE128 bytes to fill one digest of field elements.
        num_bytes_to_read = PRF_BYTES_PER_FE * config.HASH_LEN_FE
        prf_output_bytes = hashlib.shake_128(input_data).digest(num_bytes_to_read)
        return HashDigestVector(
            data=[
                Fp(value=int.from_bytes(bytes(chunk), "big"))
                for chunk in batched(prf_output_bytes, PRF_BYTES_PER_FE)
            ]
        )

    def derive_randomness(
        self,
        config: XmssConfig,
        epoch: Uint64,
        message: Bytes32,
        counter: Uint64,
    ) -> Randomness:
        """
        Derive deterministic randomness for one signing attempt.

        # Overview

        Signing maps the message onto a codeword whose digits must add up to a fixed target.
        - Each attempt folds in fresh randomness.
        - It retries with a higher counter until the digit sum lands on the target.

        Deriving that randomness from the seed makes the search reproducible.

        # Reproducibility

        A synchronized scheme signs each slot at most once.
        Signing one slot twice is treated as misbehavior.
        A deterministic attempt order means one slot and message always yield the same signature.

        Args:
            config: Active XMSS configuration.
            epoch: Slot identifier for this signature.
            message: Full message being signed.
            counter: Attempt number, incremented when a previous attempt aborted.

        Returns:
            Randomness used to encode the message into a valid codeword.
        """
        # Layout:
        #
        #     domain_sep || 0x01 || key || epoch || message || counter
        input_data = (
            PRF_DOMAIN_SEP
            + PRF_DOMAIN_SEP_RANDOMNESS
            + self
            + epoch.to_bytes(4, "big")
            + message
            + counter.to_bytes(8, "big")
        )

        num_bytes_to_read = PRF_BYTES_PER_FE * config.RAND_LEN_FE
        prf_output_bytes = hashlib.shake_128(input_data).digest(num_bytes_to_read)
        return Randomness(
            data=[
                Fp(value=int.from_bytes(bytes(chunk), "big"))
                for chunk in batched(prf_output_bytes, PRF_BYTES_PER_FE)
            ]
        )
