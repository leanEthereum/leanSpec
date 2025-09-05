"""Gossipsub protocol parameters."""

from lean_spec.subspecs.chain.config import DEVNET_CONFIG
from lean_spec.types import StrictBaseModel


class GossipsubParameters(StrictBaseModel):
    """A model holding the canonical gossipsub parameters."""

    protocol_id: str = "/meshsub/1.0.0"
    """The protocol ID for gossip messages."""

    d: int = 8
    """The target number of peers for a stable gossip mesh topic."""

    d_low: int = 6
    """
    The low watermark for the number of peers in a stable gossip mesh topic.
    """

    d_high: int = 12
    """
    The high watermark for the number of peers in a stable gossip mesh topic.
    """

    d_lazy: int = 6
    """The target number of peers for gossip-only connections."""

    heartbeat_interval_secs: float = 0.7
    """The frequency of the gossipsub heartbeat in seconds."""

    fanout_ttl_secs: int = 60
    """The time-to-live for fanout maps in seconds."""

    mcache_len: int = 6
    """The number of history windows to retain full messages in the cache."""

    mcache_gossip: int = 3
    """The number of history windows to gossip about."""

    seen_ttl_secs: int = (
        DEVNET_CONFIG.second_per_slot * DEVNET_CONFIG.justification_lookback_slots * 2
    )
    """
    The expiry time in seconds for the cache of seen message IDs.

    This is calculated as SECONDS_PER_SLOT * JUSTIFICATION_LOOKBACK_SLOTS * 2.
    """
