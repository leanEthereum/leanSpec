"""
Gossipsub topics

- Allowed GossipTopic.
- Allowed Payload annotated with the payload type.
"""

from enum import Enum

from pydantic import Field
from typing_extensions import Annotated

from lean_spec.subspecs.containers.block.block import SignedBlock
from lean_spec.subspecs.containers.vote import SignedVote

BlockPayload = Annotated[SignedBlock, Field(description="Payload for block topic.")]
VotePayload = Annotated[SignedVote, Field(description="Payload for vote topic.")]


class GossipTopic(str, Enum):
    """Enum representing allowed gossip topics and their payload types."""

    BLOCK = BlockPayload
    VOTE = VotePayload
