"""Poseidon hash engine in compression and sponge modes for the Generalized XMSS scheme."""

from itertools import batched

from pydantic import PrivateAttr

from lean_spec.base import StrictBaseModel
from lean_spec.spec.ssz import Uint64

from ..koalabear import Fp
from ..poseidon import (
    PARAMS_16,
    PARAMS_24,
    Poseidon,
    PoseidonParams,
)
from .constants import TWEAK_PREFIX_CHAIN, TWEAK_PREFIX_TREE, XmssConfig
from .field import int_to_base_p
from .types import ChainTweak, HashDigestVector, Parameter, TreeTweak


class PoseidonXmss(StrictBaseModel):
    """Poseidon hash engine wrapper used inside the XMSS scheme."""

    params16: PoseidonParams
    """Permutation parameters for the width-16 state."""

    params24: PoseidonParams
    """Permutation parameters for the width-24 state."""

    _engines: dict[int, Poseidon] = PrivateAttr(default_factory=dict)

    def _get_engine(self, width: int) -> Poseidon:
        """Return a cached Poseidon engine for the given width.

        Raises:
            ValueError: When the width is neither 16 nor 24.
        """
        if width not in self._engines:
            match width:
                case 16:
                    params = self.params16
                case 24:
                    params = self.params24
                case _:
                    raise ValueError(f"Width must be 16 or 24, got {width}")
            self._engines[width] = Poseidon(params)
        return self._engines[width]

    def compress(self, input_vec: list[Fp], width: int, output_length: int) -> list[Fp]:
        """Poseidon in compression mode.

        Computes Truncate(Permute(padded_input) + padded_input).
        The padded input is the original vector zero-extended to the state width.
        The feed-forward addition is part of the Poseidon design and is required
        for security.
        Used for hash chains and Merkle interior nodes.

        Args:
            input_vec: Field elements to hash.
            width: Permutation state width, either 16 or 24.
            output_length: Number of output field elements to return.

        Returns:
            Truncated digest of output_length field elements.
        """
        # The output cannot be longer than the input vector after padding.
        if len(input_vec) < output_length:
            raise ValueError("Input vector is too short for requested output length.")

        # Select the cached engine matching the requested permutation width.
        engine = self._get_engine(width)

        # Zero-pad to the state width before applying the permutation.
        padded_input = list(input_vec) + [Fp(value=0)] * (width - len(input_vec))

        # Permute, then add the original padded input element-wise.
        permuted_state = engine.permute(padded_input)
        final_state = [p + i for p, i in zip(permuted_state, padded_input, strict=True)]

        return final_state[:output_length]

    def safe_domain_separator(self, lengths: list[int], capacity_length: int) -> list[Fp]:
        """Build a capacity initialization vector for the sponge construction.

        Hashes the packed length parameters into a fixed-size capacity value.
        This prevents collisions between sponges that absorb data of different shapes.

        Args:
            lengths: Integer parameters that define the hash context.
            capacity_length: Number of field elements in the returned capacity value.

        Returns:
            A capacity vector of length capacity_length.
        """
        # Pack all lengths into a single unambiguous integer using 32-bit slots.
        acc = 0
        for length in lengths:
            acc = (acc << 32) | length

        # Compress the decomposed vector through the width-24 engine.
        # Width 24 is the only mode used for sponge domain separation.
        input_vec = int_to_base_p(acc, 24)
        return self.compress(input_vec, 24, capacity_length)

    def sponge(
        self,
        input_vec: list[Fp],
        capacity_value: list[Fp],
        output_length: int,
        width: int,
    ) -> list[Fp]:
        """Poseidon in sponge mode.

        Phase 1: load capacity, zero-extend input to a multiple of the rate.
        Phase 2: absorb each rate-sized chunk by replacement, then permute.
        Phase 3: squeeze the rate slots until output_length elements are produced.

        Args:
            input_vec: Variable-length input.
            capacity_value: Domain-separating capacity initialization.
            output_length: Desired output length in field elements.
            width: Permutation state width.

        Returns:
            A digest of output_length field elements.
        """
        # The capacity must leave at least one rate slot for absorbing input.
        if len(capacity_value) >= width:
            raise ValueError("Capacity length must be smaller than the state width.")

        engine = self._get_engine(width)
        rate = width - len(capacity_value)

        # Zero-pad to a multiple of the rate so absorption iterates exact chunks.
        num_extra = (rate - (len(input_vec) % rate)) % rate
        padded_input = input_vec + [Fp(value=0)] * num_extra

        # Layout: capacity slots first, then rate slots.
        cap_length = len(capacity_value)
        state = [Fp(value=0)] * width
        state[:cap_length] = capacity_value

        # Phase 2: absorb each chunk by overwriting the rate slots.
        for chunk in batched(padded_input, rate):
            for j, value in enumerate(chunk):
                state[cap_length + j] = value
            state = engine.permute(state)

        # Phase 3: squeeze rate slots, permuting until enough output is available.
        output: list[Fp] = []
        while len(output) < output_length:
            output.extend(state[cap_length : cap_length + rate])
            state = engine.permute(state)

        return output[:output_length]

    def tweak_hash(
        self,
        config: XmssConfig,
        parameter: Parameter,
        tweak: TreeTweak | ChainTweak,
        message_parts: list[HashDigestVector],
    ) -> HashDigestVector:
        """Apply the tweakable hash to one or more digests.

        Mode selection:

        - One digest input uses width-16 compression for hash chains.
        - Two digest inputs use width-24 compression for Merkle interior nodes.
        - More inputs use sponge mode for Merkle leaves.

        Args:
            config: Active XMSS configuration.
            parameter: Public parameter that personalizes the hash.
            tweak: Position tweak for domain separation.
            message_parts: Digests to hash together.

        Returns:
            A digest of HASH_LENGTH_FIELD_ELEMENTS field elements.
        """
        # Pack the tweak fields into one integer, then split it into base-P field elements.
        #
        # The low byte is a per-shape prefix.
        # It stops a tree tweak and a chain tweak from packing to the same value.
        # That keeps Merkle hashing domain-separated from chain hashing.
        #
        # Every other field sits in its own bit range above the prefix.
        match tweak:
            case TreeTweak(level=level, index=index):
                acc = (level << 40) | (int(index) << 8) | TWEAK_PREFIX_TREE
            case ChainTweak(epoch=epoch, chain_index=chain_index, step=step):
                acc = (int(epoch) << 24) | (chain_index << 16) | (step << 8) | TWEAK_PREFIX_CHAIN
        encoded_tweak = int_to_base_p(acc, config.TWEAK_LENGTH_FIELD_ELEMENTS)

        if len(message_parts) == 1:
            # Hash chain step: width-16 compression of (digest || parameter || tweak).
            input_vec = message_parts[0].elements + parameter.elements + encoded_tweak
            result = self.compress(input_vec, 16, config.HASH_LENGTH_FIELD_ELEMENTS)

        elif len(message_parts) == 2:
            # Merkle node: width-24 compression of (parameter || tweak || left || right).
            input_vec = (
                parameter.elements
                + encoded_tweak
                + message_parts[0].elements
                + message_parts[1].elements
            )
            result = self.compress(input_vec, 24, config.HASH_LENGTH_FIELD_ELEMENTS)

        else:
            # Merkle leaf: sponge mode over many concatenated digests.
            flattened_message = [element for part in message_parts for element in part.elements]
            input_vec = parameter.elements + encoded_tweak + flattened_message

            # The domain separator binds the sponge to this hashing task shape.
            lengths = [
                config.PARAMETER_LENGTH,
                config.TWEAK_LENGTH_FIELD_ELEMENTS,
                config.DIMENSION,
                config.HASH_LENGTH_FIELD_ELEMENTS,
            ]
            capacity_value = self.safe_domain_separator(lengths, config.CAPACITY)
            result = self.sponge(input_vec, capacity_value, config.HASH_LENGTH_FIELD_ELEMENTS, 24)

        return HashDigestVector(data=result)

    def hash_chain(
        self,
        config: XmssConfig,
        parameter: Parameter,
        epoch: Uint64,
        chain_index: int,
        start_step: int,
        num_steps: int,
        start_digest: HashDigestVector,
    ) -> HashDigestVector:
        """Iterate the tweakable hash along a Winternitz chain.

        Each iteration uses a distinct chain tweak so every step is domain-separated.

        Args:
            config: Active XMSS configuration.
            parameter: Public parameter that personalizes the hash.
            epoch: Slot identifier for the one-time signature.
            chain_index: Index of the chain within the one-time signature.
            start_step: Step number of the input digest.
            num_steps: Number of additional hash applications.
            start_digest: Digest at start_step.

        Returns:
            Digest at start_step + num_steps.
        """
        current_digest = start_digest
        for i in range(num_steps):
            # Steps are 1-indexed: step 1 is the first hash after the chain start.
            tweak = ChainTweak(epoch=epoch, chain_index=chain_index, step=start_step + i + 1)
            current_digest = self.tweak_hash(config, parameter, tweak, [current_digest])
        return current_digest


PROD_POSEIDON = PoseidonXmss(params16=PARAMS_16, params24=PARAMS_24)
"""Poseidon engine with production parameters."""

TEST_POSEIDON = PROD_POSEIDON
"""Test environment reuses the production Poseidon parameters."""
