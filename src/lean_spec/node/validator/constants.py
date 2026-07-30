"""Validator attestation-gate thresholds."""

from typing import Final

SYNC_LAG_THRESHOLD: Final[int] = 4
"""Slot lag past which the local view is too stale to attest."""

NETWORK_STALL_THRESHOLD: Final[int] = 8
"""Slot lag treated as a network-wide stall, so attestations stay live."""

HYSTERESIS_BAND: Final[int] = 2
"""Slot band holding the gate closed near the threshold, so it cannot flip slot-to-slot."""
