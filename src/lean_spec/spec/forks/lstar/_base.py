"""Shared typed base for the lstar spec mixins."""

from abc import abstractmethod
from collections.abc import Set as AbstractSet

from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AttestationData,
    Block,
    BlockBody,
    BlockHeader,
    GenesisConfig,
    Interval,
    SignedAggregatedAttestation,
    SignedBlock,
    SingleMessageAggregate,
    Slot,
    State,
    Store,
    ValidatorIndex,
    Validators,
)
from lean_spec.spec.forks.protocol import ForkProtocol
from lean_spec.spec.ssz import Bytes32

LstarStore = Store[State, Block]
"""Concrete Store specialization owned by the lstar fork."""


class LstarSpecBase(ForkProtocol):
    """Shared typed base every lstar behavior mixin inherits."""

    state_class: type[State]
    block_class: type[Block]
    block_body_class: type[BlockBody]
    block_header_class: type[BlockHeader]
    aggregated_attestations_class: type[AggregatedAttestations]
    store_class: type[LstarStore]
    attestation_data_class: type[AttestationData]
    aggregated_attestation_class: type[AggregatedAttestation]
    genesis_config_class: type[GenesisConfig]

    @abstractmethod
    def process_slots(self, state: State, target_slot: Slot) -> State:
        """Advance the state through empty slots up to the target slot."""
        ...

    @abstractmethod
    def process_block(self, state: State, block: Block) -> State:
        """Apply full block processing including header and body."""
        ...

    @abstractmethod
    def state_transition(
        self,
        state: State,
        block: Block,
    ) -> State:
        """Apply the complete state transition function for a block."""
        ...

    @abstractmethod
    def build_block(
        self,
        state: State,
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Bytes32,
        known_block_roots: AbstractSet[Bytes32],
        aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] | None = None,
    ) -> tuple[Block, State, list[AggregatedAttestation], list[SingleMessageAggregate]]:
        """Build a valid block on top of the given pre-state."""
        ...

    @abstractmethod
    def verify_signatures(
        self,
        signed_block: SignedBlock,
        validators: Validators,
    ) -> bool:
        """Verify the merged aggregate proof carried by a signed block."""
        ...

    @abstractmethod
    def prune_stale_attestation_data(self, store: LstarStore) -> LstarStore:
        """Remove attestation data that can no longer influence fork choice."""
        ...

    @abstractmethod
    def accept_new_attestations(self, store: LstarStore) -> LstarStore:
        """Migrate pending payloads into the known pool and update the head."""
        ...

    @abstractmethod
    def update_safe_target(self, store: LstarStore) -> LstarStore:
        """Update the deepest block with supermajority attestation weight."""
        ...

    @abstractmethod
    def aggregate(self, store: LstarStore) -> tuple[LstarStore, list[SignedAggregatedAttestation]]:
        """Combine raw validator votes into compact aggregated attestations."""
        ...

    @abstractmethod
    def on_tick(
        self,
        store: LstarStore,
        target_interval: Interval,
        has_proposal: bool,
        is_aggregator: bool = False,
    ) -> tuple[LstarStore, list[SignedAggregatedAttestation]]:
        """Advance store time to the target interval, performing interval actions."""
        ...
