"""
Gossipsub Parameters
====================

Configuration parameters controlling gossipsub mesh behavior.

Overview
--------

Gossipsub maintains a mesh of peers for each subscribed topic.
These parameters tune the mesh size, timing, and caching behavior.

Parameter Categories
--------------------

**Mesh Degree (D parameters):**

Controls how many peers are in the mesh for each topic.

::

    D_low <= D <= D_high

    D       Target mesh size (8 for Ethereum)
    D_low   Minimum before grafting new peers (6)
    D_high  Maximum before pruning excess peers (12)
    D_lazy  Peers to gossip IHAVE messages to (6)

**Timing:**

::

    heartbeat_interval   Mesh maintenance frequency (0.7s for Ethereum)
    fanout_ttl           How long to keep fanout peers (60s)

**Caching:**

::

    mcache_len      Total history windows kept (6)
    mcache_gossip   Windows included in IHAVE gossip (3)
    seen_ttl        Duplicate detection window

Ethereum Values
---------------

The Ethereum consensus layer specifies:

- D = 8, D_low = 6, D_high = 12, D_lazy = 6
- Heartbeat = 700ms (0.7s)
- Message cache = 6 windows, gossip last 3

References:
----------
- Ethereum P2P spec: https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md
- Gossipsub v1.0: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md
- Gossipsub v1.2: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.2.md
"""

from __future__ import annotations

from lean_spec.subspecs.chain.config import JUSTIFICATION_LOOKBACK_SLOTS, SECONDS_PER_SLOT
from lean_spec.subspecs.networking.config import GOSSIPSUB_DEFAULT_PROTOCOL_ID
from lean_spec.types import StrictBaseModel


class GossipsubParameters(StrictBaseModel):
    """Core gossipsub configuration.

    Defines the mesh topology and timing parameters.

    Default values follow the Ethereum consensus P2P specification.
    """

    protocol_id: str = GOSSIPSUB_DEFAULT_PROTOCOL_ID
    """The protocol ID for gossip messages."""

    # Mesh Degree Parameters

    d: int = 8
    """Target number of mesh peers per topic.

    The heartbeat procedure adjusts the mesh toward this size:

    - If |mesh| < D_low: graft peers up to D
    - If |mesh| > D_high: prune peers down to D
    """

    d_low: int = 6
    """Minimum mesh peers before grafting.

    When mesh size drops below this threshold, the heartbeat
    will graft new peers to reach the target D.
    """

    d_high: int = 12
    """Maximum mesh peers before pruning.

    When mesh size exceeds this threshold, the heartbeat
    will prune excess peers down to the target D.
    """

    d_lazy: int = 6
    """Number of non-mesh peers for IHAVE gossip.

    During heartbeat, IHAVE messages are sent to this many
    randomly selected peers outside the mesh. This enables
    the lazy pull protocol for reliability.
    """

    # Timing Parameters

    heartbeat_interval_secs: float = 0.7
    """Interval between heartbeat ticks in seconds.

    The heartbeat procedure runs periodically to:

    - Maintain mesh size (graft/prune)
    - Send IHAVE gossip to non-mesh peers
    - Clean up stale fanout entries
    - Shift the message cache window
    """

    fanout_ttl_secs: int = 60
    """Time-to-live for fanout entries in seconds.

    Fanout peers are used when publishing to topics we don't
    subscribe to. Entries expire after this duration of
    inactivity to free resources.
    """

    # Message Cache Parameters

    mcache_len: int = 6
    """Total number of history windows in the message cache.

    - Messages are stored for this many heartbeat intervals.
    - After mcache_len heartbeats, messages are evicted.
    """

    mcache_gossip: int = 3
    """Number of recent windows included in IHAVE gossip.

    Only messages from the most recent mcache_gossip windows
    are advertised via IHAVE. Older cached messages can still
    be retrieved via IWANT but won't be actively gossiped.
    """

    seen_ttl_secs: int = int(SECONDS_PER_SLOT) * int(JUSTIFICATION_LOOKBACK_SLOTS) * 2
    """Time-to-live for seen message IDs in seconds.

    Message IDs are tracked to detect duplicates. This should
    be long enough to cover network propagation delays but
    short enough to bound memory usage.
    """
