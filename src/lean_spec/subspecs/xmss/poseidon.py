"""
Defines the Poseidon2 hash functions for the Generalized XMSS scheme.

### The Cryptographic Engine: Why Poseidon2?

This module provides the low-level cryptographic engine for all internal hashing
operations. It is built on **Poseidon2** hash function.

The choice of Poseidon2 is deliberate and critical for the scheme's ultimate goal.
Unlike traditional hashes like SHA-3, Poseidon2 is an **arithmetization-friendly**
(or **SNARK-friendly**) hash function. Its algebraic structure is simple, making it
exponentially faster to prove and verify inside a zero-knowledge proof system,
which is essential for aggregating many signatures into a single, compact proof.

This file provides wrappers for the two primary ways Poseidon2 is used:

1.  **Compression Mode**: A fast, fixed-input-size mode for hashing small,
    predictable data structures like a single hash digest or a pair of them.
2.  **Sponge Mode**: A flexible, variable-input-size mode for hashing large
    amounts of data, like the many digests that form a Merkle tree leaf.
"""

from __future__ import annotations

from typing import List

from ..koalabear import Fp
from ..poseidon2.permutation import (
    PARAMS_16,
    PARAMS_24,
    Poseidon2Params,
    permute,
)
from .containers import HashDigest
from .utils import int_to_base_p


class PoseidonXmss:
    """An instance of the Poseidon2 hash engine for the XMSS scheme."""

    def __init__(self, params16: Poseidon2Params, params24: Poseidon2Params):
        """Initializes the hasher with specific Poseidon2 permutations."""
        self.params16 = params16
        self.params24 = params24

    def compress(self, input_vec: List[Fp], width: int, output_len: int) -> HashDigest:
        """
        Implements the Poseidon2 hash in **compression mode**.

        This mode is used for hashing fixed-size inputs and is the most efficient
        way to use Poseidon2. It is used for traversing hash chains and building
        the internal nodes of the Merkle tree.

        ### Compression Algorithm

        The function computes: `Truncate(Permute(padded_input) + padded_input)`.
        1.  **Padding**: The `input_vec` is padded with zeros to match the full state `width`.
        2.  **Permutation**: The core cryptographic permutation is applied to the padded state.
        3.  **Feed-Forward**: The original padded input is added element-wise to the
            permuted state. This is a key feature of the Poseidon2 design that
            provides security against certain attacks.
        4.  **Truncation**: The result is truncated to the desired `output_len`.

        Args:
            input_vec: The list of field elements to be hashed.
            width: The state width of the Poseidon2 permutation (16 or 24).
            output_len: The number of field elements in the output digest.

        Returns:
            A hash digest of `output_len` field elements.
        """
        # Check that the input vector is long enough to produce the output.
        if len(input_vec) < output_len:
            raise ValueError("Input vector is too short for requested output length.")

        # Select the correct permutation parameters based on the state width.
        assert width in (16, 24), "Width must be 16 or 24"
        params = self.params16 if width == 16 else self.params24

        # Create a fixed-width buffer and copy the input, padding with zeros.
        padded_input = [Fp(value=0)] * width
        padded_input[: len(input_vec)] = input_vec

        # Apply the Poseidon2 permutation.
        permuted_state = permute(padded_input, params)

        # Apply the feed-forward step, adding the input back element-wise.
        final_state = [p + i for p, i in zip(permuted_state, padded_input, strict=True)]

        # Truncate the state to the desired output length and return.
        return final_state[:output_len]

    def safe_domain_separator(self, lengths: List[int], capacity_len: int) -> List[Fp]:
        """
        Computes a unique domain separator for the sponge construction (SAFE API).

        A sponge's security relies on its initial state being unique for each distinct
        hashing task. This function creates a unique "configuration" or
        "initialization vector" (`capacity_value`) by hashing the high-level
        parameters of the sponge's usage (e.g., the dimensions of the data
        being hashed). This prevents multi-user or cross-context attacks.

        Args:
            lengths: A list of integer parameters that define the hash context.
            capacity_len: The desired length of the output capacity value.

        Returns:
            A list of `capacity_len` field elements for initializing the sponge.
        """
        # Pack all the length parameters into a single, large, unambiguous integer.
        acc = 0
        for length in lengths:
            acc = (acc << 32) | length

        # Decompose this integer into a fixed-size list of field elements.
        #
        # This list serves as the input to a one-off compression hash.
        # NOTE: we always use this mode with a 24 width.
        input_vec = int_to_base_p(acc, 24)

        # Compress the decomposed vector to produce the capacity value.
        return self.compress(input_vec, 24, capacity_len)

    def sponge(
        self,
        input_vec: List[Fp],
        capacity_value: List[Fp],
        output_len: int,
        width: int,
    ) -> HashDigest:
        """
        Implements the Poseidon2 hash using the **sponge construction**.

        This mode is used for hashing large or variable-length inputs. In this scheme,
        it is specifically used to hash the Merkle tree leaves, which consist of many
        concatenated hash digests.

        ### Sponge Algorithm

        1.  **Initialization**: The internal state is divided into a `rate` (for data)
            and a `capacity` (for security). The `capacity` part is initialized
            with the domain-separating `capacity_value`.

        2.  **Absorbing**: The input data is processed in `rate`-sized chunks. In each
            step, a chunk is added to the `rate` part of the state, and then the
            entire state is scrambled by the `permute` function.

        3.  **Squeezing**: Once all input is absorbed, the `rate` part of the state is
            extracted as output. If more output is needed, the state is permuted again,
            and more is extracted, repeating until `output_len` elements are generated.

        Args:
            input_vec: The input data of arbitrary length.
            capacity_value: The domain-separating value from `safe_domain_separator`.
            output_len: The number of field elements in the final output digest.
            width: The width of the Poseidon2 permutation.

        Returns:
            A hash digest of `output_len` field elements.
        """
        # Ensure that the capacity value is not too long.
        if len(capacity_value) >= width:
            raise ValueError("Capacity length must be smaller than the state width.")

        # Determine the permutation parameters and the size of the rate.
        assert width in (16, 24), "Width must be 16 or 24"
        params = self.params16 if width == 16 else self.params24
        rate = width - len(capacity_value)

        # Pad the input vector with zeros to be an exact multiple of the rate size.
        num_extra = (rate - (len(input_vec) % rate)) % rate
        padded_input = input_vec + [Fp(value=0)] * num_extra

        # Initialize the state:
        # - rate part is zero,
        # - capacity part is the domain separator.
        state = [Fp(value=0)] * width
        state[rate:] = capacity_value

        # Absorb the input in rate-sized chunks.
        for i in range(0, len(padded_input), rate):
            chunk = padded_input[i : i + rate]
            # Add the chunk to the rate part of the state.
            for j in range(rate):
                state[j] += chunk[j]
            # Apply the cryptographic permutation to mix the state.
            state = permute(state, params)

        # Squeeze the output until enough elements have been generated.
        output: HashDigest = []
        while len(output) < output_len:
            # Extract the rate part of the state as output.
            output.extend(state[:rate])
            # Permute the state.
            state = permute(state, params)

        # Truncate to the final output length and return.
        return output[:output_len]


# An instance configured for production-level parameters.
PROD_POSEIDON = PoseidonXmss(PARAMS_16, PARAMS_24)

# A lightweight instance for test environments.
TEST_POSEIDON = PoseidonXmss(PARAMS_16, PARAMS_24)
