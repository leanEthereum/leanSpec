"""Chain and Consensus Configuration Specification"""

from typing_extensions import Final

from lean_spec.types.uint import Uint64

# --- Time Parameters ---

INTERVALS_PER_SLOT = Uint64(5)
"""Number of intervals per slot for forkchoice processing."""

SECONDS_PER_SLOT: Final = Uint64(4)
"""The fixed duration of a single slot in seconds."""

MILLISECONDS_PER_SLOT: Final = SECONDS_PER_SLOT * Uint64(1000)
"""The fixed duration of a single slot in milliseconds."""

MILLISECONDS_PER_INTERVAL = MILLISECONDS_PER_SLOT // INTERVALS_PER_SLOT
"""Milliseconds per forkchoice processing interval."""

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
