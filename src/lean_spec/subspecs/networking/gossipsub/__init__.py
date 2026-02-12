"""
Gossipsub Protocol Implementation
=================================

Gossipsub is a mesh-based pubsub protocol combining:

1. **Eager push** within topic meshes for low-latency delivery
2. **Lazy pull** via gossip (IHAVE/IWANT) for reliability

Key Concepts
------------

- **Mesh**: Full message exchange with D peers per topic
- **Fanout**: Temporary peers for publish-only topics
- **Gossip**: IHAVE/IWANT for message dissemination to non-mesh peers
- **IDONTWANT**: Bandwidth optimization (v1.2)

References:
----------
- Gossipsub v1.0: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md
- Gossipsub v1.2: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.2.md
- Ethereum P2P: https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md
"""

from .behavior import (
    GossipsubBehavior,
)
from .message import GossipsubMessage
from .parameters import (
    GossipsubParameters,
)
from .rpc import (
    ControlGraft,
    ControlIDontWant,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    ProtobufDecodeError,
)
from .topic import (
    ForkMismatchError,
    GossipTopic,
    TopicKind,
    format_topic_string,
    parse_topic_string,
)
from .types import (
    MessageId,
    TopicId,
)

__all__ = [
    # Behavior (main entry point)
    "GossipsubBehavior",
    "GossipsubParameters",
    # Message
    "GossipsubMessage",
    # Topic (commonly needed for Ethereum)
    "GossipTopic",
    "TopicKind",
    "format_topic_string",
    "parse_topic_string",
    "ForkMismatchError",
    # Types
    "MessageId",
    "TopicId",
    # Control messages (for custom handlers)
    "ControlMessage",
    "ControlGraft",
    "ControlPrune",
    "ControlIHave",
    "ControlIWant",
    "ControlIDontWant",
    # Errors
    "ProtobufDecodeError",
]
