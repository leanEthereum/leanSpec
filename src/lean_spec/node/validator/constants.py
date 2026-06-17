"""Validator duty-gate thresholds"""

from typing import Final

SYNC_LAG_THRESHOLD: Final[int] = 4
"""Slot lag past which the local view is too stale to sign."""

NETWORK_STALL_THRESHOLD: Final[int] = 8
"""Slot lag treated as a network-wide stall, so duties stay live (twice the local gate)."""

HYSTERESIS_BAND: Final[int] = 2
"""Slot band holding the gate closed near the threshold, so it cannot flip slot-to-slot."""
