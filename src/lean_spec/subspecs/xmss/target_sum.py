"""
Implements the Top Level Target Sum Winternitz incomparable encoding scheme.

This module provides the logic for converting a message hash into a valid
codeword for the one-time signature part of the scheme. It acts as a filter on
top of the message hash output.
"""

from typing import List, Optional

from .constants import PROD_CONFIG, TEST_CONFIG, XmssConfig
from .containers import Parameter, Randomness
from .message_hash import (
    PROD_MESSAGE_HASHER,
    TEST_MESSAGE_HASHER,
    MessageHasher,
)


class TargetSumEncoder:
    """
    An instance of the Target Sum encoder for a given configuration.

    This class encapsulates the logic for validating a message hash against the
    scheme's target sum constraint.
    """

    def __init__(self, config: XmssConfig, message_hasher: MessageHasher):
        """Initializes the encoder with a specific parameter set."""
        self.config = config
        self.message_hasher = message_hasher

    def encode(
        self, parameter: Parameter, message: bytes, rho: Randomness, epoch: int
    ) -> Optional[List[int]]:
        """
        Encodes a message into a codeword if it meets the target sum criteria.

        ### Encoding Algorithm

        1.  **Hashing to a Vertex**: The function first hashes the inputs (`message`,
            `rho`, etc.) to produce a candidate codeword. This can be viewed as
            mapping the inputs to a vertex in a high-dimensional hypercube, where
            the vertex's coordinates are the digits of the codeword.

        2.  **Target Sum Validation**: It then checks if the sum of the candidate's digits
            matches the scheme's predefined `TARGET_SUM`. This is equivalent to
            verifying that the vertex lies on the correct hypercube layer. This
            constraint is critical for the scheme's security and ensures a
            predictable number of hash operations during signature verification.

        Args:
            parameter: The public parameter `P`, used for domain separation.
            message: The message to encode.
            rho: The randomness used for this specific encoding attempt.
            epoch: The current epoch, used as part of the hash input.

        Returns:
            - The codeword (a list of integers) if the sum matches the target.
            - Otherwise, it returns `None` to signal that this attempt failed and
            a new `rho` must be tried.
        """
        # Hash the inputs to map them to a potential codeword (a vertex in the hypercube).
        codeword_candidate = self.message_hasher.apply(parameter, epoch, rho, message)

        # A codeword is valid only if it lies on the predefined hypercube layer.
        #
        # This is verified by checking if the sum of its coordinates equals TARGET_SUM.
        if sum(codeword_candidate) == self.config.TARGET_SUM:
            # If the sum is correct, this is a valid codeword for the one-time signature.
            return codeword_candidate
        else:
            # If the sum does not match, this `rho` is invalid for
            # this message.
            #
            # The caller (the `sign` function) will need to try again with new
            # randomness.
            return None


PROD_TARGET_SUM_ENCODER = TargetSumEncoder(PROD_CONFIG, PROD_MESSAGE_HASHER)
"""An instance configured for production-level parameters."""

TEST_TARGET_SUM_ENCODER = TargetSumEncoder(TEST_CONFIG, TEST_MESSAGE_HASHER)
"""A lightweight instance for test environments."""
