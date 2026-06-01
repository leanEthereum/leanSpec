"""Lstar fork — identity and construction facade."""

from typing import ClassVar

from ..protocol import ForkProtocol
from ._contract import LstarSpecContract, LstarStore
from .aggregation import AggregationMixin
from .block_production import BlockProductionMixin
from .containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AttestationData,
    Block,
    BlockBody,
    BlockHeader,
    Config,
    State,
)
from .fork_choice import ForkChoiceMixin
from .signatures import SignatureMixin
from .state_transition import StateTransitionMixin
from .timeline import TimelineMixin
from .validator_duties import ValidatorDutiesMixin

__all__ = ["LstarSpec", "LstarStore"]


class LstarSpec(
    StateTransitionMixin,
    SignatureMixin,
    BlockProductionMixin,
    ForkChoiceMixin,
    AggregationMixin,
    TimelineMixin,
    ValidatorDutiesMixin,
    LstarSpecContract,
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
    config_class: type[Config] = Config
