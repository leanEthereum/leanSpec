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
        """
        Advance store time by one interval and perform interval-specific actions.

        Different actions are performed based on interval within slot:
        - Interval 0: Process attestations if proposal exists
        - Interval 1: Validator attesting period (no action)
        - Interval 2: Aggregators create proofs & broadcast
        - Interval 3: Update safe target (fast confirm)
        - Interval 4: Process accumulated attestations
        """
        # Advance time by one interval
        store = store.model_copy(update={"time": store.time + Interval(1)})
        current_interval = Interval(int(store.time) % int(INTERVALS_PER_SLOT))
        new_aggregates: list[SignedAggregatedAttestation] = []

        if current_interval == Interval(0) and has_proposal:
            store = self.accept_new_attestations(store)
        elif current_interval == Interval(2) and is_aggregator:
            store, new_aggregates = self.aggregate(store)
        elif current_interval == Interval(3):
            store = self.update_safe_target(store)
        elif current_interval == Interval(4):
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

        Ticks store forward interval by interval, performing appropriate
        actions for each interval type. This method handles time progression
        incrementally to ensure all interval-specific actions are performed.
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
