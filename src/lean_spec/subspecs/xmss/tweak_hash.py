"""
Defines the Tweakable Hash function using Poseidon2.

### The Problem: Hash Function Overload

In a complex cryptographic scheme like XMSS, a single hash function (like Poseidon2)
is used for many different purposes:
1.  Hashing iteratively to form **hash chains**.
2.  Hashing pairs of nodes to build the **Merkle tree**.
3.  Hashing the one-time public key to form a **Merkle leaf**.

If we simply called `hash(data)` for all these cases, we could run into a critical
security issue: a "collision" between different contexts. For example, the output of a
hash in a chain might accidentally be identical to the hash of two nodes in the tree.
This could allow an attacker to create forgeries.

### The Solution: Tweakable Hashing

A **tweakable hash function** solves this by treating each hash computation as having a
unique "address" or "tweak".

The function's signature becomes `hash(tweak, data)`. By ensuring every tweak is
unique across the entire scheme, we guarantee that every hash computation is
**domain-separated**, eliminating the risk of cross-context collisions.
"""

from __future__ import annotations

from itertools import chain
from typing import List, Union

from pydantic import Field

from lean_spec.types.base import StrictBaseModel

from ..koalabear import Fp
from .constants import (
    PROD_CONFIG,
    TEST_CONFIG,
    TWEAK_PREFIX_CHAIN,
    TWEAK_PREFIX_TREE,
    XmssConfig,
)
from .containers import HashDigest, Parameter
from .poseidon import (
    PROD_POSEIDON,
    TEST_POSEIDON,
    PoseidonXmss,
)
from .utils import int_to_base_p


class TreeTweak(StrictBaseModel):
    """
    A tweak used for hashing nodes within the Merkle tree.

    This structure ensures that every hash computed during the construction of the
    Merkle tree has a unique context.
    """

    level: int = Field(
        ge=0, description="The level (height) in the Merkle tree, where 0 is the leaf level."
    )
    index: int = Field(ge=0, description="The node's index (from the left) within that level.")


class ChainTweak(StrictBaseModel):
    """
    A tweak used for hashing elements within a WOTS+ hash chain.

    This structure ensures every iterative hash within every one-time signature
    chain is distinct across all epochs.
    """

    epoch: int = Field(ge=0, description="The signature epoch.")
    chain_index: int = Field(
        ge=0, description="The index of the hash chain (from 0 to DIMENSION-1)."
    )
    step: int = Field(ge=0, description="The step number within the chain (from 1 to BASE-1).")


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
        Encodes a structured tweak object into a list of field elements.

        It converts a high-level tweak context (like "Merkle tree, level 5, index 3")
        into a low-level format that can be consumed by the Poseidon2 hash function.

        ### Encoding Algorithm

        1.  **Packing**: The integer components of the tweak are packed into a
            single, large integer using bit-shifting. A unique prefix
            (`TWEAK_PREFIX_TREE` or `TWEAK_PREFIX_CHAIN`) is included to
            guarantee that `TreeTweak` and `ChainTweak` can never produce
            the same integer. This process is injective (one-to-one).

        2.  **Decomposition**: The resulting large integer is then decomposed into a
            list of base-`P` digits, where `P` is the field prime. This produces the
            final list of field elements.

        Args:
            tweak: The `TreeTweak` or `ChainTweak` object to encode.
            length: The desired number of field elements in the output list.

        Returns:
            A list of `length` field elements representing the encoded tweak.
        """
        # Pack the tweak's integer fields into a single large integer.
        #
        # A hardcoded prefix is included for domain separation between tweak types.
        if isinstance(tweak, TreeTweak):
            # Packing scheme: (level << 40) | (index << 8) | PREFIX
            acc = (tweak.level << 40) | (tweak.index << 8) | TWEAK_PREFIX_TREE.value
        else:
            # Packing scheme: (epoch << 24) | (chain_index << 16) | (step << 8) | PREFIX
            acc = (
                (tweak.epoch << 24)
                | (tweak.chain_index << 16)
                | (tweak.step << 8)
                | TWEAK_PREFIX_CHAIN.value
            )

        # Decompose the packed integer `acc` into a list of base-P field elements.
        return int_to_base_p(acc, length)

    def apply(
        self,
        parameter: Parameter,
        tweak: Tweak,
        message_parts: List[HashDigest],
    ) -> HashDigest:
        """
        Applies the tweakable Poseidon2 hash function to a message.

        This is the main entry point for all internal hashing operations. It prepares
        the inputs and routes them to the appropriate Poseidon2 function based on
        the input size, ensuring optimal performance and security.

        ### Hashing Algorithm

        1.  **Input Assembly**: The final hash input is formed by concatenating:
            `[parameter || encoded_tweak || flattened_message_parts]`

        2.  **Mode Selection**:
            - For small inputs (1 or 2 `HashDigest` parts), it uses the highly
                efficient **compression mode** of Poseidon2.
            - For large inputs (many `HashDigest` parts, like a Merkle leaf),
                it uses the more flexible **sponge mode**.

        Args:
            parameter: The public parameter `P` for this key pair.
            tweak: A `TreeTweak` or `ChainTweak` for domain separation.
            message_parts: A list of one or more hash digests to be hashed together.

        Returns:
            A new hash digest of `HASH_LEN_FE` field elements.
        """
        # Get the config for this scheme.
        config = self.config

        # Encode the high-level tweak structure into a list of field elements.
        encoded_tweak = self._encode_tweak(tweak, config.TWEAK_LEN_FE)

        # Route to the correct Poseidon2 mode based on the input size.
        if len(message_parts) == 1:
            # Case 1: Hashing a single digest (used in hash chains).
            #
            # We use the efficient width-16 compression mode.
            input_vec = parameter + encoded_tweak + message_parts[0]
            return self.poseidon.compress(input_vec, 16, config.HASH_LEN_FE)

        elif len(message_parts) == 2:
            # Case 2: Hashing two digests (used for Merkle tree nodes).
            #
            # We use the slightly larger width-24 compression mode.
            input_vec = parameter + encoded_tweak + message_parts[0] + message_parts[1]
            return self.poseidon.compress(input_vec, 24, config.HASH_LEN_FE)

        else:
            # Case 3: Hashing many digests (used for the Merkle tree leaf).
            #
            # We use the robust sponge mode.
            # First, flatten the list of message parts into a single vector.
            flattened_message = list(chain.from_iterable(message_parts))
            input_vec = parameter + encoded_tweak + flattened_message

            # Create a domain separator for the sponge mode based on the input dimensions.
            #
            # This ensures the sponge is uniquely configured for this specific hashing task.
            lengths = [
                config.PARAMETER_LEN,
                config.TWEAK_LEN_FE,
                config.DIMENSION,
                config.HASH_LEN_FE,
            ]
            capacity_value = self.poseidon.safe_domain_separator(lengths, config.CAPACITY)

            return self.poseidon.sponge(input_vec, capacity_value, config.HASH_LEN_FE, 24)

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

        This function iteratively calls the main `apply` method, creating a new,
        unique `ChainTweak` for each step to ensure every hash in the sequence
        is domain-separated.

        Args:
            parameter: The public parameter `P`.
            epoch: The signature epoch, part of the tweak.
            chain_index: The index of the hash chain, part of the tweak.
            start_step: The starting step number in the chain.
            num_steps: The number of hashing steps to perform.
            start_digest: The digest to begin hashing from.

        Returns:
            The final hash digest after `num_steps` applications.
        """
        current_digest = start_digest
        for i in range(num_steps):
            # Create a unique tweak for the current position in the chain.
            #
            # The `step` is `start_step + i + 1` because steps are 1-indexed.
            tweak = ChainTweak(epoch=epoch, chain_index=chain_index, step=start_step + i + 1)
            # Apply the hash function to get the next digest in the chain.
            current_digest = self.apply(parameter, tweak, [current_digest])
        return current_digest


PROD_TWEAK_HASHER = TweakHasher(PROD_CONFIG, PROD_POSEIDON)
"""An instance configured for production-level parameters."""

TEST_TWEAK_HASHER = TweakHasher(TEST_CONFIG, TEST_POSEIDON)
"""A lightweight instance for test environments."""
