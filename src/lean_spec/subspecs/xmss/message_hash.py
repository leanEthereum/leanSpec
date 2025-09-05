"""
Defines the "Top Level" message hashing for the signature scheme.

### The Challenge: Efficiently Finding a Valid Codeword

The "Target Sum" signature scheme requires the signer to find a `codeword` whose
digits sum to a specific value. This is equivalent to hashing a message and hoping the
output is on a single, specific "layer" of a high-dimensional hypercube. The
probability of this can be low, forcing the signer to try many times with different
randomness (`rho`).

### The Solution: "Top Level" Hashing

This module implements a more efficient approach. Instead of targeting a single layer,
we define a valid codeword as any vertex that lies within the **top `D` layers** of the
hypercube (where `D` is `FINAL_LAYER` in the configuration). This significantly
increases the target space, drastically reducing the number of retries the signer needs.

This process involves three main stages:
1.  **Input Preparation**: All inputs (message, epoch, randomness, etc.) are
    unambiguously encoded into a uniform format (lists of field elements).
2.  **Extended Hashing**: Poseidon2 is called iteratively to generate a long,
    pseudorandom output digest, effectively behaving like an eXtendable-Output
    Function (XOF).
3.  **Mapping to Hypercube**: The long digest is treated as a large number, which
    is then safely and deterministically mapped to a unique vertex within the
    allowed top layers of the hypercube.
"""

from __future__ import annotations

from typing import List

from lean_spec.subspecs.xmss.poseidon import (
    PROD_POSEIDON,
    TEST_POSEIDON,
    PoseidonXmss,
)

from ..koalabear import Fp, P
from .constants import (
    PROD_CONFIG,
    TEST_CONFIG,
    TWEAK_PREFIX_MESSAGE,
    XmssConfig,
)
from .containers import Parameter, Randomness
from .hypercube import (
    hypercube_find_layer,
    hypercube_part_size,
    map_to_vertex,
)
from .utils import int_to_base_p


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
        which is then decomposed into its base-`P` representation, where `P`
        is the field prime. This provides a canonical mapping from bytes to
        the algebraic structure required by Poseidon2.
        """
        # Interpret the 32 little-endian bytes as a single large integer.
        acc = int.from_bytes(message, "little")

        # Decompose the integer into a list of field elements (base-P).
        return int_to_base_p(acc, self.config.MSG_LEN_FE)

    def encode_epoch(self, epoch: int) -> List[Fp]:
        """
        Encodes the epoch and a domain separator prefix into field elements.

        This function packs the epoch and the message hash prefix into a single
        integer, then decomposes it. This ensures the epoch is included in the
        hash input in a structured, domain-separated way.
        """
        # Combine the epoch and the message hash prefix into a single integer.
        acc = (epoch << 8) | TWEAK_PREFIX_MESSAGE.value

        # Decompose the integer into its base-P representation.
        return int_to_base_p(acc, self.config.TWEAK_LEN_FE)

    def _map_into_hypercube_part(self, field_elements: List[Fp]) -> List[int]:
        """
        Maps a long, pseudorandom digest to a unique vertex within the top layers
        of the signature hypercube.

        This is the core of the "Top Level" strategy. It takes a large, uniformly
        random number and maps it to a point in a smaller, highly structured set.

        ### Mapping Algorithm

        1.  **Integer Reconstruction**: The input list of field elements is
            interpreted as the base-P representation of a single, very large integer.

        2.  **Modular Reduction**: This integer is reduced modulo the `domain_size`,
            which is the total number of vertices in the target top layers. This
            step maps the large random value to a unique index within the target set.

        3.  **Index to Vertex**: This unique index is then deterministically
            converted first into a `(layer, offset)` pair, and finally into the
            specific coordinates of the corresponding hypercube vertex.
        """
        # Get the config for this scheme.
        config = self.config

        # Combine field elements into one large integer (big-endian, base-P).
        acc = 0
        for fe in field_elements:
            acc = acc * P + fe.value

        # Reduce this integer modulo the size of the target domain.
        #
        # The target domain is the set of all vertices in layers 0..FINAL_LAYER.
        domain_size = hypercube_part_size(config.BASE, config.DIMENSION, config.FINAL_LAYER)
        acc %= domain_size

        # Find which layer the resulting index falls into, and its offset.
        layer, offset = hypercube_find_layer(config.BASE, config.DIMENSION, acc)

        # Map the offset within the layer to a unique vertex.
        return map_to_vertex(config.BASE, config.DIMENSION, layer, offset)

    def apply(
        self,
        parameter: Parameter,
        epoch: int,
        rho: Randomness,
        message: bytes,
    ) -> List[int]:
        """
        Applies the full "Top Level" message hash and mapping procedure.

        This function generates a long pseudorandom digest by iteratively calling
        Poseidon2 and then maps this digest to a candidate codeword (a vertex in
        the hypercube).

        ### Hashing with Extended Output

        A single Poseidon2 compression call produces a relatively short output. To
        generate a sufficiently large random number for the hypercube mapping, this
        function calls Poseidon2 multiple times in a loop. The iteration number `i`
        is used as a domain separator for each call, effectively creating a simple
        eXtendable-Output Function (XOF) from the fixed-output hash.

        Args:
            parameter: The public parameter `P`.
            epoch: The current epoch.
            rho: A random value `rho` to ensure a unique hash output.
            message: The 32-byte message to be hashed.

        Returns:
            A candidate codeword, represented as a list of `DIMENSION` integers
            (the coordinates of a vertex in the hypercube).
        """
        # Encode the message and epoch as field elements.
        message_fe = self.encode_message(message)
        epoch_fe = self.encode_epoch(epoch)

        # Iteratively call Poseidon2 to generate a long hash output.
        poseidon_outputs: List[Fp] = []
        for i in range(self.config.POS_INVOCATIONS):
            # Use the iteration number as a domain separator for each hash call.
            iteration_separator = [Fp(value=i)]

            # The input is: rho || P || epoch || message || iteration.
            combined_input = rho + parameter + epoch_fe + message_fe + iteration_separator

            # Hash the combined input using Poseidon2 compression mode.
            iteration_output = self.poseidon.compress(
                combined_input, 24, self.config.POS_OUTPUT_LEN_PER_INV_FE
            )
            poseidon_outputs.extend(iteration_output)

        # Map the final aggregated list of field elements into a hypercube vertex.
        return self._map_into_hypercube_part(poseidon_outputs)


PROD_MESSAGE_HASHER = MessageHasher(PROD_CONFIG, PROD_POSEIDON)
"""An instance configured for production-level parameters."""

TEST_MESSAGE_HASHER = MessageHasher(TEST_CONFIG, TEST_POSEIDON)
"""A lightweight instance for test environments."""
