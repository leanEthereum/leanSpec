"""Gossipsub topics"""

from enum import Enum
from typing import Any, Type

from lean_spec.subspecs.containers.block.block import SignedBlock
from lean_spec.subspecs.containers.vote import SignedVote


class GossipTopic(Enum):
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

    BLOCK = ("block", SignedBlock)
    """
    Topic for gossiping new blocks.

    - `value`: "block"
    - `payload_type`: `SignedBlock`
    """

    VOTE = ("vote", SignedVote)
    """
    Topic for gossiping new votes (attestations).

    - `value`: "vote"
    - `payload_type`: `SignedVote`
    """
