"""
Defines the "Top Level" message hashing for the signature scheme.

This module implements the logic for hashing a message into the top layers of
a hypercube, which is the first step in the "Top Level Target Sum" encoding.

The process involves:
1.  Encoding the message, epoch, and randomness into field elements.
2.  Hashing these elements with Poseidon2 to produce a digest.
3.  Interpreting the digest as a large integer and mapping it to a unique
    vertex within the allowed top layers of the hypercube.
"""

from __future__ import annotations

from typing import List

from lean_spec.subspecs.xmss.poseidon import (
    PROD_POSEIDON,
    TEST_POSEIDON,
    PoseidonXmss,
)
from lean_spec.subspecs.xmss.utils import int_to_base_p

from ..koalabear import Fp, P
from .constants import (
    PROD_CONFIG,
    TEST_CONFIG,
    TWEAK_PREFIX_MESSAGE,
    XmssConfig,
)
from .hypercube import find_layer, get_hypercube_part_size, map_to_vertex
from .structures import Parameter, Randomness


class MessageHasher:
    """An instance of the "Top Level" message hasher for a given config."""

    def __init__(self, config: XmssConfig, poseidon_hasher: PoseidonXmss):
        """Initializes the hasher with a specific parameter set."""
        self.config = config
        self.poseidon = poseidon_hasher

    def encode_message(self, message: bytes) -> List[Fp]:
        """
        Encodes a 32-byte message into a list of field elements.

        The message bytes are interpreted as a single little-endian integer,
        which is then decomposed into its base-`P` representation.
        """
        # Interpret the little-endian bytes as a single large integer.
        acc = int.from_bytes(message, "little")

        # Decompose the integer into a list of field elements (base-P).
        return int_to_base_p(acc, self.config.MSG_LEN_FE)

    def encode_epoch(self, epoch: int) -> List[Fp]:
        """Encodes epoch and domain separator into a list of field elements."""
        # Combine the epoch and the message hash prefix into a single integer.
        acc = (epoch << 8) | TWEAK_PREFIX_MESSAGE.value

        # Decompose the integer into its base-P representation.
        return int_to_base_p(acc, self.config.TWEAK_LEN_FE)

    def _map_into_hypercube_part(self, field_elements: List[Fp]) -> List[int]:
        """
        Maps a list of field elements to a vertex in
        the top `FINAL_LAYER` layers.
        """
        # Get the config for this scheme.
        config = self.config

        # Combine field elements into one large integer (big-endian, base-P).
        acc = 0
        for fe in field_elements:
            acc = acc * P + fe.value

        # Reduce this integer modulo the size of the target domain.
        #
        # The target domain is the set of all vertices
        # in layers 0..FINAL_LAYER.
        domain_size = get_hypercube_part_size(
            config.BASE, config.DIMENSION, config.FINAL_LAYER
        )
        acc %= domain_size

        # Find which layer the resulting index falls into, and its offset.
        layer, offset = find_layer(config.BASE, config.DIMENSION, acc)

        # Map the offset within the layer to a unique vertex.
        return map_to_vertex(config.BASE, config.DIMENSION, layer, offset)

    def apply(
        self,
        parameter: Parameter,
        epoch: int,
        randomness: Randomness,
        message: bytes,
    ) -> List[int]:
        """
        Applies the full "Top Level" message hash procedure.

        This involves multiple invocations of Poseidon2, with the
        combined output mapped into a specific region of the hypercube.

        Args:
            parameter: The public parameter `P`.
            epoch: The current epoch.
            randomness: A random value `rho`.
            message: The 32-byte message to be hashed.

        Returns:
            A vertex in the hypercube, represented as a list
            of `DIMENSION` ints.
        """
        # Encode the message and epoch as field elements.
        message_fe = self.encode_message(message)
        epoch_fe = self.encode_epoch(epoch)

        # Iteratively call Poseidon2 to generate a long hash output.
        poseidon_outputs: List[Fp] = []
        for i in range(self.config.POS_INVOCATIONS):
            # Use the iteration number as a domain separator for
            # each hash call.
            iteration_separator = [Fp(value=i)]

            # The input is: rho || P || epoch || message || iteration.
            combined_input = (
                randomness
                + parameter
                + epoch_fe
                + message_fe
                + iteration_separator
            )

            # Hash the combined input using Poseidon2 compression mode.
            iteration_output = self.poseidon.compress(
                combined_input, 24, self.config.POS_OUTPUT_LEN_PER_INV_FE
            )
            poseidon_outputs.extend(iteration_output)

        # Map the final list of field elements into a hypercube vertex.
        return self._map_into_hypercube_part(poseidon_outputs)


PROD_MESSAGE_HASHER = MessageHasher(PROD_CONFIG, PROD_POSEIDON)
"""An instance configured for production-level parameters."""

TEST_MESSAGE_HASHER = MessageHasher(TEST_CONFIG, TEST_POSEIDON)
"""A lightweight instance for test environments."""
