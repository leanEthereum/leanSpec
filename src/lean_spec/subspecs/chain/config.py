"""
Chain and Consensus Configuration Specification

This file defines the core consensus parameters and chain presets for the
Lean Consensus Experimental Chain.
"""

from pydantic import BaseModel, ConfigDict
from typing_extensions import Final

from lean_spec.types import BasisPoint, Uint64

# --- Time Parameters ---

INTERVALS_PER_SLOT = Uint64(4)
"""Number of intervals per slot for forkchoice processing."""

SLOT_DURATION_MS: Final = Uint64(4000)
"""The fixed duration of a single slot in milliseconds."""

SECONDS_PER_SLOT: Final = SLOT_DURATION_MS // Uint64(1000)
"""The fixed duration of a single slot in seconds."""

SECONDS_PER_INTERVAL = SECONDS_PER_SLOT // INTERVALS_PER_SLOT
"""Seconds per forkchoice processing interval."""

JUSTIFICATION_LOOKBACK_SLOTS: Final = Uint64(3)
"""The number of slots to lookback for justification."""

PROPOSER_REORG_CUTOFF_BPS: Final = Uint64(2500)
"""
The deadline within a slot (in basis points) for a proposer to publish a
block.

Honest validators may re-org blocks published after this cutoff.

(2500 bps = 25% of slot duration).
"""

VOTE_DUE_BPS: Final = Uint64(5000)
"""
The deadline within a slot (in basis points) by which validators must
submit their votes.

(5000 bps = 50% of slot duration).
"""

FAST_CONFIRM_DUE_BPS: Final = Uint64(7500)
"""
The deadline within a slot (in basis points) for achieving a fast
confirmation.

(7500 bps = 75% of slot duration).
"""

VIEW_FREEZE_CUTOFF_BPS: Final = Uint64(7500)
"""
The cutoff within a slot (in basis points) after which the current view is
considered 'frozen', preventing further changes.

(7500 bps = 75% of slot duration).
"""

# --- State List Length Presets ---

HISTORICAL_ROOTS_LIMIT: Final = Uint64(2**18)
"""
The maximum number of historical block roots to store in the state.

With a 4-second slot, this corresponds to a history
of approximately 12.1 days.
"""

STAKER_REGISTRY_LIMIT: Final = Uint64(2**12)
"""The maximum number of stakers that can be in the registry."""

class _ChainConfig(BaseModel):
    """
    A model holding the canonical, immutable configuration constants
    for the chain.
    """

    # Configuration to make the model immutable.
    model_config = ConfigDict(frozen=True, extra="forbid")

    # Time Parameters
    slot_duration_ms: Uint64
    second_per_slot: Uint64
    justification_lookback_slots: Uint64
    proposer_reorg_cutoff_bps: BasisPoint
    vote_due_bps: BasisPoint
    fast_confirm_due_bps: BasisPoint
    view_freeze_cutoff_bps: BasisPoint

    # State List Length Presets
    historical_roots_limit: Uint64
    staker_registry_limit: Uint64


# The Devnet Chain Configuration.
DEVNET_CONFIG: Final = _ChainConfig(
    slot_duration_ms=SLOT_DURATION_MS,
    second_per_slot=SECONDS_PER_SLOT,
    justification_lookback_slots=JUSTIFICATION_LOOKBACK_SLOTS,
    proposer_reorg_cutoff_bps=PROPOSER_REORG_CUTOFF_BPS,
    vote_due_bps=VOTE_DUE_BPS,
    fast_confirm_due_bps=FAST_CONFIRM_DUE_BPS,
    view_freeze_cutoff_bps=VIEW_FREEZE_CUTOFF_BPS,
    historical_roots_limit=HISTORICAL_ROOTS_LIMIT,
    staker_registry_limit=STAKER_REGISTRY_LIMIT,
)
