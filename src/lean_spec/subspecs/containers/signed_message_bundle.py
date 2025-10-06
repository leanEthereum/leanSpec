"""Message Bundle Containers."""

from lean_spec.types.container import Container
from lean_spec.subspecs.xmss.containers import Signature

from .block import Block
from .vote import Vote


class SignedMessageBundle(Container):
    """Represents a validator's signed message bundle."""

    block_message: Block
    """The block message."""

    vote_data: Vote
    """The vote data."""

    signature: Signature
    """The signature of the message bundle."""
