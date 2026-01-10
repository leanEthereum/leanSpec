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

# --- Validator Lifecycle Parameters ---

MIN_ACTIVATION_DELAY: Final = Uint64(8)
"""
Minimum number of slots a validator must wait before activation.

This delay ensures:
1. The deposit is finalized before activation
2. Network participants see the deposit before validator is active
3. Time for validation and consensus on the new validator
"""

MIN_EXIT_DELAY: Final = Uint64(8)
"""
Minimum number of slots from exit request to actual removal.

This delay ensures:
1. Ongoing attestations from exiting validator can complete
2. Chain stability during validator set changes
3. Clean handoff of validator responsibilities
"""

MAX_ACTIVATIONS_PER_SLOT: Final = Uint64(4)
"""
Maximum number of validators that can activate in a single slot.

Rate limiting prevents:
1. Sudden validator set size changes
2. State bloat from mass activations
3. Consensus instability from rapid composition changes
"""

MAX_EXITS_PER_SLOT: Final = Uint64(4)
"""
Maximum number of validators that can exit in a single slot.

Similar to activation limiting, this ensures gradual validator set changes.
"""


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

    # Validator Lifecycle Parameters
    min_activation_delay: Uint64
    min_exit_delay: Uint64
    max_activations_per_slot: Uint64
    max_exits_per_slot: Uint64


# The Devnet Chain Configuration.
DEVNET_CONFIG: Final = _ChainConfig(
    seconds_per_slot=SECONDS_PER_SLOT,
    justification_lookback_slots=JUSTIFICATION_LOOKBACK_SLOTS,
    historical_roots_limit=HISTORICAL_ROOTS_LIMIT,
    validator_registry_limit=VALIDATOR_REGISTRY_LIMIT,
    min_activation_delay=MIN_ACTIVATION_DELAY,
    min_exit_delay=MIN_EXIT_DELAY,
    max_activations_per_slot=MAX_ACTIVATIONS_PER_SLOT,
    max_exits_per_slot=MAX_EXITS_PER_SLOT,
)
