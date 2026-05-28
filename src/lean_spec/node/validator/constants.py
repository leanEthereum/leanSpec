"""Validator duty-gate thresholds.

Informative, not normative:

- Shape when this node signs.
- Do not change what consensus accepts.
- Clients may diverge without breaking interop.
"""

from typing import Final

SYNC_LAG_THRESHOLD: Final[int] = 4
"""Slot lag past which the local view is too stale to sign.

Why:
    We justify and finalize within a handful of slots.
    A 4-slot lag is one full justification window behind real time.
    A vote from that view lands on a subtree the network has left.
"""

NETWORK_STALL_THRESHOLD: Final[int] = 8
"""Slot lag past which the whole network is treated as stalled.

Why:
    Set to twice the local threshold (8 = 2 * 4).
    Ordinary jitter at the local boundary must not trip this branch.

Effect:
    Even the freshest locally validated block is 8 slots behind.
    The cause is a streak of skipped proposals, not this node lagging.
    Duties stay live so the chain can advance through the gap.
"""

HYSTERESIS_BAND: Final[int] = 2
"""Slot band that holds the gate closed near the threshold.

Why:
    Without a band a single late gossip block flips the decision.
    Slot-over-slot flips would stutter the attestation stream.

Effect:
    Once closed, the gate reopens only when lag drops to 4 - 2 = 2.
"""
