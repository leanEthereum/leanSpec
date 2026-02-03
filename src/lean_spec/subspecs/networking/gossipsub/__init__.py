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

from lean_spec.subspecs.networking.varint import decode_varint, encode_varint

from ..transport import PeerId
from .behavior import (
    GossipsubBehavior,
    GossipsubMessageEvent,
    GossipsubPeerEvent,
    PeerState,
)
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
from .rpc import (
    RPC,
    PeerInfo,
    SubOpts,
    create_graft_rpc,
    create_ihave_rpc,
    create_iwant_rpc,
    create_prune_rpc,
    create_publish_rpc,
    create_subscription_rpc,
)
from .rpc import (
    ControlGraft as RPCControlGraft,
)
from .rpc import (
    ControlIDontWant as RPCControlIDontWant,
)
from .rpc import (
    ControlIHave as RPCControlIHave,
)
from .rpc import (
    ControlIWant as RPCControlIWant,
)
from .rpc import (
    ControlMessage as RPCControlMessage,
)
from .rpc import (
    ControlPrune as RPCControlPrune,
)
from .rpc import (
    Message as RPCMessage,
)
from .topic import (
    BLOCK_TOPIC_NAME,
    ENCODING_POSTFIX,
    TOPIC_PREFIX,
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
    # Behavior
    "GossipsubBehavior",
    "GossipsubMessageEvent",
    "GossipsubPeerEvent",
    "PeerState",
    # Message
    "GossipsubMessage",
    "SnappyDecompressor",
    # Topic
    "GossipTopic",
    "TopicKind",
    "TOPIC_PREFIX",
    "ENCODING_POSTFIX",
    "BLOCK_TOPIC_NAME",
    "ForkMismatchError",
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
    # RPC (wire protocol encoding)
    "RPC",
    "SubOpts",
    "RPCMessage",
    "RPCControlMessage",
    "RPCControlGraft",
    "RPCControlPrune",
    "RPCControlIHave",
    "RPCControlIWant",
    "RPCControlIDontWant",
    "PeerInfo",
    "create_subscription_rpc",
    "create_graft_rpc",
    "create_prune_rpc",
    "create_ihave_rpc",
    "create_iwant_rpc",
    "create_publish_rpc",
    "encode_varint",
    "decode_varint",
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
