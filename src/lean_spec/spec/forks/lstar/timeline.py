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

        Each slot is split into five intervals so consensus work runs at fixed points
        relative to when a block arrives and votes spread across the network.

        Timing of the action points within a slot:

        - Interval 0: ingest the slot's pending votes once the proposal has landed.
        - Interval 2: aggregators bundle the slot's votes into proofs and broadcast them.
        - Interval 3: advance the safe target from the latest votes for fast confirmation.
        - Interval 4: ingest the votes that accumulated through the rest of the slot.

        Aggregation waits until interval 2 so a block proposed at the slot start has
        time to propagate and gather votes before they are bundled.
        Fast confirmation sits at interval 3, after aggregates exist, so the safe
        target reflects the freshest votes the node has seen.
        """
        store = store.model_copy(update={"time": store.time + Interval(1)})
        interval_within_slot = int(store.time) % int(INTERVALS_PER_SLOT)
        new_aggregates: list[SignedAggregatedAttestation] = []

        match interval_within_slot:
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

        while store.time < target_interval:
            next_interval = Interval(int(store.time) + 1)
            should_signal_proposal = has_proposal and next_interval == target_interval

            store, new_aggregates = self.tick_interval(store, should_signal_proposal, is_aggregator)
            all_new_aggregates.extend(new_aggregates)

        return store, all_new_aggregates
