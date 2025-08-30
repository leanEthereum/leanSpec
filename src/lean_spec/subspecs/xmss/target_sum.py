"""
Implements the Top Level Target Sum Winternitz incomparable encoding scheme.

This module provides the logic for converting a message hash into a valid
codeword for the one-time signature part of the scheme. It acts as a filter on
top of the message hash output.
"""

from typing import List, Optional

from .constants import PROD_CONFIG, TEST_CONFIG, XmssConfig
from .message_hash import (
    PROD_MESSAGE_HASHER,
    TEST_MESSAGE_HASHER,
    MessageHasher,
)
from .structures import Parameter, Randomness


class TargetSumEncoder:
    """An instance of the Target Sum encoder for a given config."""

    def __init__(self, config: XmssConfig, message_hasher: MessageHasher):
        """Initializes the encoder with a specific parameter set."""
        self.config = config
        self.message_hasher = message_hasher

    def encode(
        self, parameter: Parameter, message: bytes, rho: Randomness, epoch: int
    ) -> Optional[List[int]]:
        """
        Encodes a message into a codeword if it meets the target sum criteria.

        This function first uses the message hash to map the input to a vertex
        in the hypercube. It then checks if the sum of the vertex's coordinates
        matches the scheme's `TARGET_SUM`. This filtering step is the core of
        the Target Sum scheme.

        Args:
            parameter: The public parameter `P`.
            message: The message to encode.
            rho: The randomness used for this encoding attempt.
            epoch: The current epoch.

        Returns:
            The codeword (a list of integers) if the sum is correct,
            otherwise `None`.
        """
        # Apply the message hash to get a potential codeword (a vertex).
        codeword_candidate = self.message_hasher.apply(
            parameter, epoch, rho, message
        )

        # Check if the candidate satisfies the target sum condition.
        if sum(codeword_candidate) == self.config.TARGET_SUM:
            # If the sum is correct, this is a valid codeword.
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
