"""Lstar fork — interval ticking and time progression."""

from lean_spec.spec.forks.lstar._base import LstarSpecBase, LstarStore
from lean_spec.spec.forks.lstar.config import (
    INTERVALS_PER_SLOT,
)
from lean_spec.spec.forks.lstar.containers import (
    Interval,
    SignedAggregatedAttestation,
)


class TimelineMixin(LstarSpecBase):
    """Interval ticking and time progression for the lstar fork."""

    def tick_interval(
        self,
        store: LstarStore,
        has_proposal: bool,
        is_aggregator: bool = False,
    ) -> tuple[LstarStore, list[SignedAggregatedAttestation]]:
        """Advance store time by one interval and perform interval-specific actions."""
        # Advance time by one interval
        store = store.model_copy(update={"time": store.time + Interval(1)})
        current_interval = Interval(int(store.time) % int(INTERVALS_PER_SLOT))
        new_aggregates: list[SignedAggregatedAttestation] = []

        match int(current_interval):
            # Slot start: ingest pending attestations once the slot's proposal lands.
            case 0 if has_proposal:
                store = self.accept_new_attestations(store)
            # Aggregators build proofs over the slot's attestations and broadcast them.
            case 2 if is_aggregator:
                store, new_aggregates = self.aggregate(store)
            # Fast-confirmation point: advance the safe target from the latest votes.
            case 3:
                store = self.update_safe_target(store)
            # Ingest the attestations that accumulated through the slot.
            case 4:
                store = self.accept_new_attestations(store)

        return store, new_aggregates

    def on_tick(
        self,
        store: LstarStore,
        target_interval: Interval,
        has_proposal: bool,
        is_aggregator: bool = False,
    ) -> tuple[LstarStore, list[SignedAggregatedAttestation]]:
        """
        Advance forkchoice store time to given interval count.

        Stepping one interval at a time runs every interval's action without skipping any.
        """
        all_new_aggregates: list[SignedAggregatedAttestation] = []

        # Tick forward one interval at a time
        while store.time < target_interval:
            # Check if proposal should be signaled for next interval
            next_interval = Interval(int(store.time) + 1)
            should_signal_proposal = has_proposal and next_interval == target_interval

            # Advance by one interval with appropriate signaling
            store, new_aggregates = self.tick_interval(store, should_signal_proposal, is_aggregator)
            all_new_aggregates.extend(new_aggregates)

        return store, all_new_aggregates
