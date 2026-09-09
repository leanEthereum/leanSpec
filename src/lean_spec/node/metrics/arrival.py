"""
Gossip arrival timing.

Every consensus message has an interval it was due in. A block belongs at
the start of its own slot, an attestation one interval later, an aggregate at
the aggregation interval. Measuring each arrival against that boundary turns
"the network feels slow" into a number.

The histograms record the absolute distance, so an arrival early by 200ms and
one late by 200ms share a bucket. The counters' `position` label separates
them: `before`, `inside`, or `after` the interval the message was due in.
`inside` means that interval specifically. An attestation for slot 10 landing
during slot 10's aggregation interval counts as `after`, since it missed the
attestation-production interval it was actually due in.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from lean_spec.node.metrics.registry import registry as metrics
from lean_spec.spec.forks.lstar.config import (
    MILLISECONDS_PER_INTERVAL,
    MILLISECONDS_PER_SLOT,
)

if TYPE_CHECKING:
    from lean_spec.node.chain.clock import SlotClock
    from lean_spec.spec.forks import Slot

BLOCK_PUBLICATION_INTERVAL = 0
"""Interval within a slot at which that slot's block is published."""

ATTESTATION_PRODUCTION_INTERVAL = 1
"""Interval within a slot at which validators attest to it."""

AGGREGATION_INTERVAL = 2
"""Interval within a slot at which aggregators publish proofs (see timeline.py)."""

MAX_MEASURABLE_SLOT_DISTANCE = 256
"""
Slots away from the arrival beyond which a message stops being a timing sample.

A gossip message carries its own slot, and that field is attacker-controlled
until the store validates it. `Slot` is a `Uint64`, so a peer can claim slot
2**64-1 and push a single observation of roughly 7e19 seconds into the
histogram, which pins `_sum` for the lifetime of the process and ruins every
average derived from it. Python bigints absorb that silently.

The top bucket is 16 seconds, four slots, so this bound keeps every
distinguishable bucket and 64 times the margin above it. Anything past it is
malformed or a sync artifact rather than a late arrival, and gets dropped
instead of clamped so the histogram stays a record of real messages.
"""


def _interval_start_ms(anchor_slot: int, interval_within_slot: int) -> int:
    """Milliseconds since genesis at which an interval of a given slot begins."""
    slot_start = anchor_slot * int(MILLISECONDS_PER_SLOT)
    return slot_start + interval_within_slot * int(MILLISECONDS_PER_INTERVAL)


def _interval_delta_ms(
    arrival_ms: int,
    anchor_slot: int,
    interval_within_slot: int,
) -> int:
    """
    Signed milliseconds from an interval boundary to an arrival.

    A negative result means the message beat the interval it was due in.
    """
    return arrival_ms - _interval_start_ms(anchor_slot, interval_within_slot)


def _latest_interval_delta_ms(arrival_ms: int, interval_within_slot: int) -> int:
    """
    Milliseconds since the most recent boundary of an interval, any slot.

    Anchoring to the latest boundary at or before the arrival keeps the result
    in `[0, MILLISECONDS_PER_SLOT)`, so this never goes negative.

    Known limitation, shared with the ethlambda implementation this mirrors:
    the modulo wraps rather than clamps, so a message that beat the boundary
    it was aimed at reports as nearly a full slot late instead of as `before`.
    A receiver whose clock lags the sender by more than the network latency
    sees this, and the protocol budgets a whole interval of skew via
    GOSSIP_DISPARITY_INTERVALS. The same wrap applies to any arrival in slot 0
    ahead of the first boundary, which anchors to one that never happened.
    Both clients agree on the number, so the series stay comparable; read a
    hard mode near one full slot as suspected clock skew rather than as
    genuinely late aggregation.
    """
    offset = interval_within_slot * int(MILLISECONDS_PER_INTERVAL)
    return (arrival_ms - offset) % int(MILLISECONDS_PER_SLOT)


def _is_measurable(arrival_ms: int, message_slot: int) -> bool:
    """Whether a message's own slot is close enough to be a timing sample."""
    arrival_slot = arrival_ms // int(MILLISECONDS_PER_SLOT)
    return abs(message_slot - arrival_slot) <= MAX_MEASURABLE_SLOT_DISTANCE


def _position(delta_ms: int) -> str:
    """Classify a signed delta against the width of one interval."""
    if delta_ms < 0:
        return "before"
    if delta_ms < int(MILLISECONDS_PER_INTERVAL):
        return "inside"
    return "after"


def observe_block_arrival(clock: SlotClock, block_slot: Slot) -> None:
    """
    Record a gossip block's arrival against interval 0 of its own slot.

    Call this for blocks received from a peer only. A block this node produced
    reaches the store through the same handler, and stamping it would sample
    this node's own build latency as if it were network timing. Blocks pulled
    over req/resp during sync land long after they were due, and folding those
    in would measure catch-up speed rather than gossip health.
    """
    arrival_ms = int(clock.milliseconds_since_genesis())
    if not _is_measurable(arrival_ms, int(block_slot)):
        return
    delta_ms = _interval_delta_ms(arrival_ms, int(block_slot), BLOCK_PUBLICATION_INTERVAL)
    metrics.lean_gossip_block_arrival_delay_seconds.observe(abs(delta_ms) / 1000.0)
    metrics.lean_gossip_block_arrival_total.labels(position=_position(delta_ms)).inc()


def observe_attestation_arrival(clock: SlotClock, data_slot: Slot) -> None:
    """
    Record a gossip attestation's arrival against interval 1 of its data slot.

    Peer-received attestations only, for the reason given on
    [`observe_block_arrival`]: a validator's own votes are signed locally and
    would pile up in the first bucket.
    """
    arrival_ms = int(clock.milliseconds_since_genesis())
    if not _is_measurable(arrival_ms, int(data_slot)):
        return
    delta_ms = _interval_delta_ms(arrival_ms, int(data_slot), ATTESTATION_PRODUCTION_INTERVAL)
    metrics.lean_gossip_attestation_arrival_delay_seconds.observe(abs(delta_ms) / 1000.0)
    metrics.lean_gossip_attestation_arrival_total.labels(position=_position(delta_ms)).inc()


def observe_aggregate_arrival(clock: SlotClock) -> None:
    """
    Record a gossip aggregate's arrival, against the latest aggregation boundary.

    Deliberately takes no slot. An aggregate published at the aggregation
    interval of slot N can carry a data slot well below N when it is catching
    up on an earlier group, and anchoring to that data slot would fill the
    histogram with multi-slot values that are not a health problem. Taking no
    slot also means this helper needs no guard against an implausible one,
    unlike its block and attestation counterparts.

    Peer-received aggregates only. An aggregate this node produced never
    crosses the network, so its timing reports local proving cost rather than
    anything about gossip, and
    `lean_pq_sig_aggregated_signatures_building_time_seconds` already measures
    that directly. A node that aggregates but receives nothing therefore
    reports an empty profile here, which is the honest reading: it has no
    gossip arrivals to describe.
    """
    delta_ms = _latest_interval_delta_ms(
        int(clock.milliseconds_since_genesis()),
        AGGREGATION_INTERVAL,
    )
    metrics.lean_gossip_aggregation_arrival_delay_seconds.observe(abs(delta_ms) / 1000.0)
    metrics.lean_gossip_aggregation_arrival_total.labels(position=_position(delta_ms)).inc()
