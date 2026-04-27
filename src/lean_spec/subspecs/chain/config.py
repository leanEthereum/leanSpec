"""Chain and Consensus Configuration Specification"""

from typing import Final

from lean_spec.types import Uint8, Uint64

INTERVALS_PER_SLOT: Final = Uint64(5)
"""Number of intervals per slot for forkchoice processing."""

GOSSIP_DISPARITY_INTERVALS: Final = Uint64(1)
"""
Future-slot tolerance for gossip attestations, in intervals.

Bounds the clock skew the time check is willing to absorb when admitting
a vote whose slot has not yet started locally.

One interval is roughly 800 ms.
"""

SECONDS_PER_SLOT: Final = Uint64(4)
"""The fixed duration of a single slot in seconds."""

MILLISECONDS_PER_SLOT: Final = SECONDS_PER_SLOT * Uint64(1000)
"""The fixed duration of a single slot in milliseconds."""

MILLISECONDS_PER_INTERVAL: Final = MILLISECONDS_PER_SLOT // INTERVALS_PER_SLOT
"""Milliseconds per forkchoice processing interval."""

JUSTIFICATION_LOOKBACK_SLOTS: Final = Uint64(3)
"""The number of slots to lookback for justification."""

HISTORICAL_ROOTS_LIMIT: Final = Uint64(2**18)
"""
The maximum number of historical block roots to store in the state.

With a 4-second slot, this corresponds to a history
of approximately 12.1 days.
"""

VALIDATOR_REGISTRY_LIMIT: Final = Uint64(2**12)
"""The maximum number of validators that can be in the registry."""

ATTESTATION_COMMITTEE_COUNT: Final = Uint64(1)
"""The number of attestation committees per slot."""

MAX_ATTESTATIONS_DATA: Final = Uint8(16)
"""Maximum number of distinct attestation data entries per block."""
