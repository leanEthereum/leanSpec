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
from lean_spec.spec.ssz import Bytes32, Uint64

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
    def generate_genesis(self, genesis_time: Uint64, validators: Validators) -> State:
        """Genesis-construction contract."""
        ...

    @abstractmethod
    def process_slots(self, state: State, target_slot: Slot) -> State:
        """Slot-advance contract."""
        ...

    @abstractmethod
    def process_block(self, state: State, block: Block) -> State:
        """Block-processing contract."""
        ...

    @abstractmethod
    def state_transition(
        self,
        state: State,
        block: Block,
    ) -> State:
        """State-transition contract."""
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
        """Block-building contract."""
        ...

    @abstractmethod
    def verify_signatures(
        self,
        signed_block: SignedBlock,
        validators: Validators,
    ) -> bool:
        """Signature-verification contract."""
        ...

    @abstractmethod
    def prune_stale_attestation_data(self, store: LstarStore) -> LstarStore:
        """Attestation-pruning contract."""
        ...

    @abstractmethod
    def accept_new_attestations(self, store: LstarStore) -> LstarStore:
        """Pending-attestation acceptance contract."""
        ...

    @abstractmethod
    def update_safe_target(self, store: LstarStore) -> LstarStore:
        """Safe-target update contract."""
        ...

    @abstractmethod
    def aggregate(self, store: LstarStore) -> tuple[LstarStore, list[SignedAggregatedAttestation]]:
        """Vote-aggregation contract."""
        ...

    @abstractmethod
    def on_tick(
        self,
        store: LstarStore,
        target_interval: Interval,
        has_proposal: bool,
        is_aggregator: bool = False,
    ) -> tuple[LstarStore, list[SignedAggregatedAttestation]]:
        """Interval-tick contract."""
        ...
