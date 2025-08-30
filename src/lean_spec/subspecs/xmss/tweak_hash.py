"""
Defines the Tweakable Hash function using Poseidon2.

This module implements the core hashing logic for the XMSS scheme, including:
1.  **Tweak Encoding**: Domain-separating different hash usages (chains/trees).
2.  **Poseidon2 Compression**: Hashing fixed-size inputs.
3.  **Poseidon2 Sponge**: Hashing variable-length inputs (e.g., leaf nodes).
4.  **A unified `apply` function** that dispatches to the correct mode.
5.  **A `chain` utility** to perform repeated hashing for WOTS chains.
"""

from __future__ import annotations

from itertools import chain
from typing import List, Union

from pydantic import Field

from lean_spec.subspecs.xmss.poseidon import (
    PROD_POSEIDON,
    TEST_POSEIDON,
    PoseidonXmss,
)
from lean_spec.subspecs.xmss.utils import int_to_base_p
from lean_spec.types.base import StrictBaseModel

from ..koalabear import Fp
from .constants import (
    PROD_CONFIG,
    TEST_CONFIG,
    TWEAK_PREFIX_CHAIN,
    TWEAK_PREFIX_TREE,
    XmssConfig,
)
from .structures import HashDigest, Parameter


class TreeTweak(StrictBaseModel):
    """A tweak used for hashing nodes within the Merkle tree."""

    level: int = Field(ge=0, description="The level in the Merkle tree.")
    index: int = Field(ge=0, description="The node's index within that level.")


class ChainTweak(StrictBaseModel):
    """A tweak used for hashing elements within a WOTS+ hash chain."""

    epoch: int = Field(ge=0, description="The signature epoch.")
    chain_index: int = Field(ge=0, description="The index of the hash chain.")
    step: int = Field(ge=0, description="The step number within the chain.")


class TweakHasher:
    """An instance of the Tweakable Hasher for a given config."""

    def __init__(self, config: XmssConfig, poseidon_hasher: PoseidonXmss):
        """Initializes the hasher with a specific parameter set."""
        self.config = config
        self.poseidon = poseidon_hasher

    Tweak = Union[TreeTweak, ChainTweak]
    """A type alias representing any valid tweak structure."""

    def _encode_tweak(self, tweak: Tweak, length: int) -> List[Fp]:
        """
        Encodes a tweak structure into a list of field elements for hashing.

        This function packs the tweak's integer components into a single large
        integer, then performs a base-`P` decomposition to get field elements.
        This ensures a unique and deterministic mapping from any tweak to a
        format consumable by the hash function.

        The packing scheme is designed to be injective:
        - `TreeTweak`: `(level << 40) | (index << 8) | TWEAK_PREFIX_TREE`
        - `ChainTweak`: `(epoch << 24) | (chain_index << 16)
        | (step << 8) | TWEAK_PREFIX_CHAIN`

        Args:
            tweak: The `TreeTweak` or `ChainTweak` object.
            length: The desired number of field elements in the output list.

        Returns:
            A list of `length` field elements representing the encoded tweak.
        """
        # Pack the tweak's integer fields into a single large integer.
        #
        # A unique prefix is included for domain separation.
        if isinstance(tweak, TreeTweak):
            acc = (
                (tweak.level << 40)
                | (tweak.index << 8)
                | TWEAK_PREFIX_TREE.value
            )
        else:
            acc = (
                (tweak.epoch << 24)
                | (tweak.chain_index << 16)
                | (tweak.step << 8)
                | TWEAK_PREFIX_CHAIN.value
            )

        # Decompose the large integer `acc` into a list of field elements.
        # This is a standard base-P decomposition.
        #
        # The number of elements is determined by the `length` parameter.
        return int_to_base_p(acc, length)

    def apply(
        self,
        parameter: Parameter,
        tweak: Tweak,
        message_parts: List[HashDigest],
    ) -> HashDigest:
        """
        Applies the tweakable Poseidon2 hash function to a message.

        This function is the main entry point for all hashing operations.
        It automatically selects the correct Poseidon2 mode
        (compression or sponge) based on the number of message parts provided.

        Args:
            parameter: The public parameter `P` for the hash function.
            tweak: A `TreeTweak` or `ChainTweak` for domain separation.
            message_parts: A list of one or more hash digests to be hashed.

        Returns:
            A new hash digest of `HASH_LEN_FE` field elements.
        """
        # Get the config for this scheme.
        config = self.config

        # Encode the tweak structure into field elements.
        encoded_tweak = self._encode_tweak(tweak, config.TWEAK_LEN_FE)

        if len(message_parts) == 1:
            # Case 1: Hashing a single digest (used in hash chains).
            #
            # We use the efficient width-16 compression mode.
            input_vec = parameter + encoded_tweak + message_parts[0]
            return self.poseidon.compress(input_vec, 16, config.HASH_LEN_FE)

        elif len(message_parts) == 2:
            # Case 2: Hashing two digests (used for Merkle tree nodes).
            #
            # We use the width-24 compression mode.
            input_vec = (
                parameter + encoded_tweak + message_parts[0] + message_parts[1]
            )
            return self.poseidon.compress(input_vec, 24, config.HASH_LEN_FE)

        else:
            # Case 3: Hashing many digests (used for the Merkle tree leaf).
            #
            # We use the robust sponge mode.
            # First, flatten the list of message parts into a single vector.
            flattened_message = list(chain.from_iterable(message_parts))
            input_vec = parameter + encoded_tweak + flattened_message

            # Create a domain separator based on the dimensions of the input.
            lengths = [
                config.PARAMETER_LEN,
                config.TWEAK_LEN_FE,
                config.DIMENSION,
                config.HASH_LEN_FE,
            ]
            capacity_value = self.poseidon.safe_domain_separator(
                lengths, config.CAPACITY
            )

            return self.poseidon.sponge(
                input_vec, capacity_value, config.HASH_LEN_FE
            )

    def hash_chain(
        self,
        parameter: Parameter,
        epoch: int,
        chain_index: int,
        start_step: int,
        num_steps: int,
        start_digest: HashDigest,
    ) -> HashDigest:
        """
        Performs repeated hashing to traverse a WOTS+ hash chain.

        Args:
            parameter: The public parameter `P`.
            epoch: The signature epoch.
            chain_index: The index of the hash chain.
            start_step: The starting step number in the chain.
            num_steps: The number of hashing steps to perform.
            start_digest: The digest to begin hashing from.

        Returns:
            The final hash digest after `num_steps` applications.
        """
        current_digest = start_digest
        for i in range(num_steps):
            # Create a unique tweak for the current position in the chain.
            tweak = ChainTweak(
                epoch=epoch, chain_index=chain_index, step=start_step + i + 1
            )
            # Apply the hash function.
            current_digest = self.apply(parameter, tweak, [current_digest])
        return current_digest


PROD_TWEAK_HASHER = TweakHasher(PROD_CONFIG, PROD_POSEIDON)
"""An instance configured for production-level parameters."""

TEST_TWEAK_HASHER = TweakHasher(TEST_CONFIG, TEST_POSEIDON)
"""A lightweight instance for test environments."""
