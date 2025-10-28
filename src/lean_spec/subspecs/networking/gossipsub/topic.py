"""Gossipsub topics"""

from enum import Enum
from typing import Any, Type

from lean_spec.subspecs.containers.attestation import SignedAttestation
from lean_spec.subspecs.containers.block.block import SignedBlockWithAttestation


class GossipsubTopic(Enum):
    """
    Enumerates gossip topics, bundling a topic's name with its payload type.

    Attributes:
        value (str): The network name of the topic (e.g., "block").
        payload_type (Type): The class representing the data structure
            of the topic's message (e.g., `SignedBlock`).
    """

    def __init__(self, value: str, payload_type: Type[Any]):
        """
        Initializes the GossipTopic.

        Args:
            value: The topic in string.
            payload_type: The associated gossip.
        """
        self._value_ = value
        self.payload_type = payload_type

    BLOCK = ("block", SignedBlockWithAttestation)
    """
    Topic for gossiping new blocks.

    - `value`: "block"
    - `payload_type`: `SignedBlockWithAttestation`
    """

    VOTE = ("vote", SignedAttestation)
    """
    Topic for gossiping new votes (attestations).

    - `value`: "vote"
    - `payload_type`: `SignedAttestation`
    """
