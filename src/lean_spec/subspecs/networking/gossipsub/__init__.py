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
- Ethereum P2P: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md
"""

from ..transport import PeerId
from .control import (
    ControlMessage,
    Graft,
    IDontWant,
    IHave,
    IWant,
    Prune,
)
from .mcache import (
    CacheEntry,
    MessageCache,
    SeenCache,
)
from .mesh import (
    FanoutEntry,
    MeshState,
    TopicMesh,
)
from .message import GossipsubMessage, SnappyDecompressor
from .parameters import (
    GossipsubParameters,
)
from .topic import (
    ATTESTATION_TOPIC_NAME,
    BLOCK_TOPIC_NAME,
    ENCODING_POSTFIX,
    TOPIC_PREFIX,
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
    # Message
    "GossipsubMessage",
    "SnappyDecompressor",
    # Topic
    "GossipTopic",
    "TopicKind",
    "TOPIC_PREFIX",
    "ENCODING_POSTFIX",
    "BLOCK_TOPIC_NAME",
    "ATTESTATION_TOPIC_NAME",
    "format_topic_string",
    "parse_topic_string",
    # Parameters
    "GossipsubParameters",
    # Control
    "ControlMessage",
    "Graft",
    "Prune",
    "IHave",
    "IWant",
    "IDontWant",
    # Mesh
    "MeshState",
    "TopicMesh",
    "FanoutEntry",
    # Cache
    "MessageCache",
    "SeenCache",
    "CacheEntry",
    # Types
    "MessageId",
    "PeerId",
    "TopicId",
]
