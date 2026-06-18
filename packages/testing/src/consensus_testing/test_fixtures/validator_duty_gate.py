"""Validator sync-lag duty gate test fixture."""

from typing import ClassVar, Literal, Self

from pydantic import model_validator

from consensus_testing.genesis import build_genesis_store
from consensus_testing.mocks import MockNetworkRequester
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from lean_spec.base import StrictBaseModel
from lean_spec.node.chain.clock import SlotClock
from lean_spec.node.sync.block_cache import BlockCache
from lean_spec.node.sync.peer_manager import PeerManager
from lean_spec.node.sync.service import SyncService
from lean_spec.node.validator import ValidatorRegistry, ValidatorService
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Slot
from lean_spec.spec.forks.lstar.containers import Block
from lean_spec.spec.ssz import Uint64


def _set_head_slot(sync_service: SyncService, head_slot: Slot) -> None:
    """Rewrite the head block so it sits at the requested slot."""
    blocks = dict(sync_service.store.blocks)
    old_head_block = blocks.pop(sync_service.store.head)
    new_head_block = Block(
        slot=head_slot,
        proposer_index=old_head_block.proposer_index,
        parent_root=old_head_block.parent_root,
        state_root=old_head_block.state_root,
        body=old_head_block.body,
    )
    new_head_root = hash_tree_root(new_head_block)
    blocks[new_head_root] = new_head_block
    sync_service.store = sync_service.store.model_copy(
        update={"blocks": blocks, "head": new_head_root}
    )


def _add_block_at_slot(sync_service: SyncService, slot: Slot) -> None:
    """Add a non-head block at the given slot as freshness evidence."""
    template_block = next(iter(sync_service.store.blocks.values()))
    new_block = Block(
        slot=slot,
        proposer_index=template_block.proposer_index,
        parent_root=template_block.parent_root,
        state_root=template_block.state_root,
        body=template_block.body,
    )
    new_block_root = hash_tree_root(new_block)
    sync_service.store = sync_service.store.model_copy(
        update={"blocks": {**sync_service.store.blocks, new_block_root: new_block}}
    )


class DutyGateInitialState(StrictBaseModel):
    """The store view the gate starts from, before any step runs."""

    head_slot: int
    """Slot of the local head block."""

    max_seen_slot: int
    """Highest slot across all locally stored blocks. Must be at or above head_slot."""

    @model_validator(mode="after")
    def validate_max_seen_at_or_above_head(self) -> Self:
        """The freshest seen slot cannot sit below the local head."""
        if self.max_seen_slot < self.head_slot:
            raise ValueError(
                f"max_seen_slot {self.max_seen_slot} is below head_slot {self.head_slot}"
            )
        return self


class DutyGateStep(StrictBaseModel):
    """One evaluation of the gate at a wall-clock slot, after an optional head move."""

    wall_clock_slot: int
    """Wall-clock slot the gate compares the local head against."""

    set_head_slot: int | None = None
    """When set, move the head to this slot before evaluating."""

    duty: Literal["block", "attestation"]
    """Duty kind passed to the gate. The gate logic is the same for both."""


class DutyGateDecision(StrictBaseModel):
    """The gate's verdict for one step, with the inputs it was computed from."""

    allow: bool
    """Whether duties run. False means the gate silenced the duty."""

    head_slot: int
    """Local head slot the gate saw for this step."""

    lag: int
    """Slots the head trails the wall clock, saturating at zero."""

    max_seen_slot: int
    """Highest stored block slot the gate saw for this step."""


class ValidatorDutyGateFixture(BaseConsensusFixture):
    """Emitted vector for the validator sync-lag duty gate."""

    initial_state: DutyGateInitialState
    """Store view the gate starts from."""

    steps: list[DutyGateStep]
    """Ordered gate evaluations, each carrying an optional head move."""

    decisions: list[DutyGateDecision]
    """Gate verdict per step, in step order."""


class ValidatorDutyGateTest(BaseTestSpec):
    """Spec for the validator sync-lag duty gate."""

    format_name: ClassVar[str] = "validator_duty_gate_test"
    description: ClassVar[str] = "Tests the validator sync-lag duty gate decision and hysteresis"

    initial_state: DutyGateInitialState
    """Store view the gate starts from."""

    steps: list[DutyGateStep]
    """Ordered gate evaluations to run against one service instance."""

    def generate(self) -> ValidatorDutyGateFixture:
        """Replay the steps through the gate and record each verdict."""
        # Keyless genesis is enough since the gate only reads block slots and the head.
        store = build_genesis_store(keyed=False)
        sync_service = SyncService(
            store=store,
            peer_manager=PeerManager(),
            block_cache=BlockCache(),
            clock=SlotClock(genesis_time=Uint64(0)),
            network=MockNetworkRequester(),
        )
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )

        _set_head_slot(sync_service, Slot(self.initial_state.head_slot))
        if self.initial_state.max_seen_slot > self.initial_state.head_slot:
            _add_block_at_slot(sync_service, Slot(self.initial_state.max_seen_slot))

        decisions: list[DutyGateDecision] = []
        for step in self.steps:
            if step.set_head_slot is not None:
                _set_head_slot(sync_service, Slot(step.set_head_slot))

            # Re-derive the gate's view to emit beside its verdict. The gate exposes
            # only the boolean, so these must mirror _is_synced_for_duties.
            head_slot = sync_service.store.blocks[sync_service.store.head].slot
            max_seen_slot = max(block.slot for block in sync_service.store.blocks.values())
            wall_clock_slot = Slot(step.wall_clock_slot)
            lag = 0 if head_slot >= wall_clock_slot else int(wall_clock_slot - head_slot)

            allow = service._is_synced_for_duties(wall_clock_slot, step.duty)

            decisions.append(
                DutyGateDecision(
                    allow=allow,
                    head_slot=int(head_slot),
                    lag=lag,
                    max_seen_slot=int(max_seen_slot),
                )
            )

        return ValidatorDutyGateFixture(
            initial_state=self.initial_state,
            steps=self.steps,
            decisions=decisions,
        )
