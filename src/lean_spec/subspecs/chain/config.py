"""
Chain and Consensus Configuration Specification

This file defines the core consensus parameters and chain presets for the
Lean Consensus Experimental Chain.
"""

from typing_extensions import Final

from lean_spec.types.base import StrictBaseModel
from lean_spec.types.uint import Uint64

# --- Time Parameters ---

INTERVALS_PER_SLOT = Uint64(4)
"""Number of intervals per slot for forkchoice processing."""

SECONDS_PER_SLOT: Final = Uint64(4)
"""The fixed duration of a single slot in seconds."""

SECONDS_PER_INTERVAL = SECONDS_PER_SLOT // INTERVALS_PER_SLOT
"""Seconds per forkchoice processing interval."""

JUSTIFICATION_LOOKBACK_SLOTS: Final = Uint64(3)
"""The number of slots to lookback for justification."""

# --- State List Length Presets ---

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

COMMITTEE_SIGNATURE_THRESHOLD_RATIO: Final = 0.9
"""Default ratio of committee signature participation required to trigger aggregation."""


class _ChainConfig(StrictBaseModel):
    """
    A model holding the canonical, immutable configuration constants
    for the chain.
    """

    # Time Parameters
    seconds_per_slot: Uint64
    justification_lookback_slots: Uint64

    # State List Length Presets
    historical_roots_limit: Uint64
    validator_registry_limit: Uint64

    # Attestation / Networking
    attestation_committee_count: Uint64

    # Aggregation behavior
    committee_signature_threshold_ratio: float


# The Devnet Chain Configuration.
DEVNET_CONFIG: Final = _ChainConfig(
    seconds_per_slot=SECONDS_PER_SLOT,
    justification_lookback_slots=JUSTIFICATION_LOOKBACK_SLOTS,
    historical_roots_limit=HISTORICAL_ROOTS_LIMIT,
    validator_registry_limit=VALIDATOR_REGISTRY_LIMIT,
    attestation_committee_count=ATTESTATION_COMMITTEE_COUNT,
    committee_signature_threshold_ratio=COMMITTEE_SIGNATURE_THRESHOLD_RATIO,
)
