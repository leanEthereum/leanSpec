"""
Gossipsub Protocol Implementation

Gossipsub is a mesh-based pubsub protocol combining:

1. **Eager push** within topic meshes for low-latency delivery
2. **Lazy pull** via gossip (IHAVE/IWANT) for reliability

Key Concepts

- **Mesh**: Full message exchange with D peers per topic
- **Fanout**: Temporary peers for publish-only topics
- **Gossip**: IHAVE/IWANT for message dissemination to non-mesh peers
- **IDONTWANT**: Bandwidth optimization (v1.2)

References:
- Gossipsub v1.0: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md
- Gossipsub v1.2: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.2.md
- Ethereum P2P: https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md
"""

from .behavior import GossipsubBehavior
from .message import GossipsubMessage
from .parameters import GossipsubParameters
from .topic import (
    ForkMismatchError,
    GossipTopic,
    TopicKind,
    parse_topic_string,
)

__all__ = [
    "GossipsubBehavior",
    "GossipsubMessage",
    "GossipsubParameters",
    "GossipTopic",
    "TopicKind",
    "parse_topic_string",
    "ForkMismatchError",
]
