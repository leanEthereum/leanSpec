"""Defines the Tweakable Hash function using the Poseidon2 permutation."""

from __future__ import annotations

from typing import List

from lean_spec.subspecs.xmss.utils import int_to_base_p

from ..koalabear import Fp
from ..poseidon2.permutation import PARAMS_16, PARAMS_24, permute
from .constants import PROD_CONFIG, TEST_CONFIG, XmssConfig
from .structures import HashDigest


class PoseidonXmss:
    """An instance of the Poseidon2-based tweakable hash for a given config."""

    def __init__(self, config: XmssConfig):
        """Initializes the hasher with a specific parameter set."""
        self.config = config

    def compress(
        self, input_vec: List[Fp], width: int, output_len: int
    ) -> HashDigest:
        """
        A low-level wrapper for Poseidon2 in compression mode.

        It computes: `Truncate(Permute(padded_input) + padded_input)`.

        Args:
            input_vec: The input data to be hashed.
            width: The state width of the Poseidon2 permutation (16 or 24).
            output_len: The number of field elements in the output digest.

        Returns:
            A hash digest of `output_len` field elements.
        """
        # Select the correct permutation parameters based on the state width.
        params = PARAMS_16 if width == 16 else PARAMS_24

        # Create a fixed-width buffer and copy the input, padding with zeros.
        padded_input = [Fp(value=0)] * width
        padded_input[: len(input_vec)] = input_vec

        # Apply the Poseidon2 permutation.
        permuted_state = permute(padded_input, params)

        # Apply the feed-forward step, adding the input back element-wise.
        final_state = [
            p + i for p, i in zip(permuted_state, padded_input, strict=True)
        ]

        # Truncate the state to the desired output length and return.
        return final_state[:output_len]

    def safe_domain_separator(
        self, lengths: List[int], capacity_len: int
    ) -> List[Fp]:
        """
        Computes a domain separator for the sponge construction.

        This function hashes a list of length parameters to create a unique
        "capacity value" that configures the sponge for a
        specific hashing task.

        Args:
            lengths: A list of integer parameters defining the hash context.
            capacity_len: The desired length of the output capacity value.

        Returns:
            A list of `capacity_len` field elements.
        """
        # Pack the length parameters into a single large integer.
        acc = 0
        for length in lengths:
            acc = (acc << 32) | length

        # Decompose the integer into a list of 24 field elements for hashing.
        #
        # 24 is the fixed input width for this specific domain separation hash.
        input_vec = int_to_base_p(acc, 24)

        # Compress the decomposed vector to produce the capacity value.
        return self.compress(input_vec, 24, capacity_len)

    def sponge(
        self, input_vec: List[Fp], capacity_value: List[Fp], output_len: int
    ) -> HashDigest:
        """
        A low-level wrapper for Poseidon2 in sponge mode.

        Args:
            input_vec: The input data of arbitrary length.
            capacity_value: A domain-separating value.
            output_len: The number of field elements in the output digest.

        Returns:
            A hash digest of `output_len` field elements.
        """
        # Use the width-24 permutation for the sponge.
        params = PARAMS_24
        width = params.width
        rate = width - len(capacity_value)

        # Pad the input vector to be an exact multiple of the rate.
        num_extra = (rate - (len(input_vec) % rate)) % rate
        padded_input = input_vec + [Fp(value=0)] * num_extra

        # Initialize the state with the capacity value.
        state = [Fp(value=0)] * width
        state[rate:] = capacity_value

        # Absorb the input in rate-sized chunks.
        for i in range(0, len(padded_input), rate):
            chunk = padded_input[i : i + rate]
            # Add the chunk to the rate part of the state.
            for j in range(rate):
                state[j] += chunk[j]
            # Apply the permutation.
            state = permute(state, params)

        # Squeeze the output until enough elements have been generated.
        output: HashDigest = []
        while len(output) < output_len:
            output.extend(state[:rate])
            state = permute(state, params)

        # Truncate to the final output length and return.
        return output[:output_len]


PROD_POSEIDON = PoseidonXmss(PROD_CONFIG)
"""An instance configured for production-level parameters."""

TEST_POSEIDON = PoseidonXmss(TEST_CONFIG)
"""A lightweight instance for test environments."""
