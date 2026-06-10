"""Lstar fork — identity and construction facade."""

from typing import ClassVar

from lean_spec.spec.forks.lstar._base import LstarSpecBase, LstarStore
from lean_spec.spec.forks.lstar.aggregation import AggregationMixin
from lean_spec.spec.forks.lstar.block_production import BlockProductionMixin
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AttestationData,
    Block,
    BlockBody,
    BlockHeader,
    GenesisConfig,
    State,
)
from lean_spec.spec.forks.lstar.fork_choice import ForkChoiceMixin
from lean_spec.spec.forks.lstar.signatures import SignatureMixin
from lean_spec.spec.forks.lstar.state_transition import StateTransitionMixin
from lean_spec.spec.forks.lstar.timeline import TimelineMixin
from lean_spec.spec.forks.lstar.validator_duties import ValidatorDutiesMixin
from lean_spec.spec.forks.protocol import ForkProtocol

__all__ = ["LstarSpec", "LstarStore"]


class LstarSpec(
    StateTransitionMixin,
    SignatureMixin,
    BlockProductionMixin,
    ForkChoiceMixin,
    AggregationMixin,
    TimelineMixin,
    ValidatorDutiesMixin,
    LstarSpecBase,
):
    """Lstar fork."""

    NAME: ClassVar[str] = "lstar"
    VERSION: ClassVar[int] = 4
    GOSSIP_DIGEST: ClassVar[str] = "12345678"

    previous: ClassVar[type[ForkProtocol] | None] = None

    state_class: type[State] = State
    block_class: type[Block] = Block
    block_body_class: type[BlockBody] = BlockBody
    block_header_class: type[BlockHeader] = BlockHeader
    aggregated_attestations_class: type[AggregatedAttestations] = AggregatedAttestations
    store_class: type[LstarStore] = LstarStore
    attestation_data_class: type[AttestationData] = AttestationData
    aggregated_attestation_class: type[AggregatedAttestation] = AggregatedAttestation
    genesis_config_class: type[GenesisConfig] = GenesisConfig
