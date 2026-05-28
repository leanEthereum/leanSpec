"""
Fork protocol interface for leanSpec consensus.

This module is deliberately agnostic of any individual devnet.
"""

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any, ClassVar, Protocol, Self

from lean_spec.spec.forks.lstar.containers import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.ssz import Bytes32, SSZList, Uint64


class SpecSSZType(Protocol):
    """Structural contract: any SSZ container exposes encode/decode."""

    def encode_bytes(self) -> bytes:
        """Serialize this container to its SSZ byte representation."""
        ...

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Deserialize an SSZ byte string into a new container instance."""
        ...


class SpecConfigType(SpecSSZType, Protocol):
    """Structural contract: any fork's genesis Config container class."""


class SpecStateType(SpecSSZType, Protocol):
    """Structural contract: any fork's State container class exposes genesis."""

    @property
    def slot(self) -> Slot:
        """Current slot of this state."""
        ...

    @property
    def config(self) -> "SpecConfigType":
        """Genesis configuration carried by the state."""
        ...


class SpecBlockType(SpecSSZType, Protocol):
    """Structural contract: any fork's Block container class."""

    @property
    def slot(self) -> Slot:
        """Slot at which the block was proposed."""
        ...

    @property
    def proposer_index(self) -> ValidatorIndex:
        """Validator index of the block's proposer."""
        ...

    @property
    def parent_root(self) -> Bytes32:
        """SSZ root of the parent block."""
        ...

    @property
    def state_root(self) -> Bytes32:
        """SSZ root of the post-state produced by applying this block."""
        ...


class SpecBlockBodyType(SpecSSZType, Protocol):
    """Structural contract: any fork's BlockBody container class.

    Carries the variable-size payload attached to a block — typically
    aggregated attestations and any future operation lists.
    """


class SpecBlockHeaderType(SpecSSZType, Protocol):
    """Structural contract: any fork's BlockHeader container class.

    The fixed-shape summary of a block used in state-transition tracking
    and state-root caching. Carries slot, proposer, parent root, state
    root, and body root.
    """


class SpecAggregatedAttestationsType(SpecSSZType, Protocol):
    """Structural contract: any fork's AggregatedAttestations list class.

    Bounded SSZ list of aggregated attestations included in a block body.
    """


class SpecSignedBlockType(SpecSSZType, Protocol):
    """Structural contract: any fork's SignedBlock container class.

    A SignedBlock wraps a Block with a single aggregated proof covering
    every attestation in the body plus the proposer's signature over
    the block root. Subspecs treat instances as opaque SSZ-encodable
    payloads passed between sync, gossip, and storage.
    """

    @property
    def block(self) -> SpecBlockType:
        """The wrapped Block payload."""
        ...


class SpecAttestationDataType(SpecSSZType, Protocol):
    """Structural contract: any fork's AttestationData container class.

    Encodes a validator's view of the chain (slot + source/target/head
    checkpoints) and is the payload that gets signed.
    """

    @property
    def slot(self) -> Slot:
        """Slot the attestation is voting at."""
        ...

    @property
    def head(self) -> Checkpoint:
        """Head checkpoint the attestation votes for."""
        ...

    @property
    def source(self) -> Checkpoint:
        """Source checkpoint of the attestation."""
        ...

    @property
    def target(self) -> Checkpoint:
        """Target checkpoint of the attestation."""
        ...


class SpecSignedAttestationType(SpecSSZType, Protocol):
    """Structural contract: any fork's SignedAttestation container class.

    A single validator's attestation bundled with its signature.
    """

    @property
    def data(self) -> SpecAttestationDataType:
        """The unsigned attestation payload."""
        ...

    @property
    def validator_id(self) -> ValidatorIndex:
        """Index of the validator that produced this attestation."""
        ...


class SpecAggregatedAttestationType(SpecSSZType, Protocol):
    """Structural contract: any fork's AggregatedAttestation container class.

    An attestation aggregated over multiple validators via a participation
    bitfield.
    """

    @property
    def data(self) -> SpecAttestationDataType:
        """The unsigned attestation payload."""
        ...


class SpecSignedAggregatedAttestationType(SpecSSZType, Protocol):
    """Structural contract: any fork's SignedAggregatedAttestation container class.

    The aggregator's broadcast payload — combined attestation data plus the
    aggregated signature proof.
    """

    @property
    def data(self) -> SpecAttestationDataType:
        """The unsigned attestation payload."""
        ...


class SpecStoreType(Protocol):
    """Structural contract: any fork's forkchoice Store.

    Exposes anchor construction plus the read/write surface that sync,
    chain, and node services drive without depending on a concrete fork.
    """

    @property
    def head(self) -> Bytes32:
        """Root of the canonical head block."""
        ...

    @property
    def safe_target(self) -> Bytes32:
        """Root of the current safe target block."""
        ...

    @property
    def latest_justified(self) -> Checkpoint:
        """Most recent justified checkpoint."""
        ...

    @property
    def latest_finalized(self) -> Checkpoint:
        """Most recent finalized checkpoint."""
        ...

    @property
    def validator_id(self) -> ValidatorIndex | None:
        """Index of the local validator owning this store, if any."""
        ...

    @property
    def blocks(self) -> Mapping[Bytes32, SpecBlockType]:
        """Mapping from block root to known Block."""
        ...

    @property
    def states(self) -> Mapping[Bytes32, SpecStateType]:
        """Mapping from block root to post-state of that block."""
        ...

    @classmethod
    def from_anchor(
        cls,
        state: SpecStateType,
        anchor_block: SpecBlockType,
        validator_id: ValidatorIndex | None,
    ) -> Self:
        """Construct a forkchoice store anchored at the given state/block."""
        ...

    def on_block(self, signed_block: "SpecSignedBlockType") -> Self:
        """Apply a signed block to the store and return the updated store."""
        ...

    def on_gossip_attestation(
        self,
        signed_attestation: "SpecSignedAttestationType",
        is_aggregator: bool,
    ) -> Self:
        """Apply a single-validator attestation and return the updated store."""
        ...

    def on_gossip_aggregated_attestation(
        self,
        signed_attestation: "SpecSignedAggregatedAttestationType",
    ) -> Self:
        """Apply an aggregated attestation and return the updated store."""
        ...


class ForkProtocol(ABC):
    """Identity and construction facade for a devnet fork."""

    NAME: ClassVar[str]
    """Fork name, e.g. 'lstar'. Must be unique across the registry."""

    VERSION: ClassVar[int]
    """Strictly monotonic version. Used to order forks in the registry."""

    GOSSIP_DIGEST: ClassVar[str]
    """
    Fork identifier embedded in gossipsub topic names.

    Must match the digest used by other clients on the same network so that
    block, attestation, and aggregation topics route compatibly.
    """

    previous: ClassVar["type[ForkProtocol] | None"]
    """
    Predecessor fork in the upgrade chain, or None for the root fork.

    Forms a linked chain that the registry can walk to derive ordering
    and that upgrade_state can traverse for cross-fork state migrations.
    """

    state_class: type[SpecStateType]
    """Concrete State container class owned by this fork."""

    block_class: type[SpecBlockType]
    """Concrete Block container class owned by this fork."""

    block_body_class: type[SpecBlockBodyType]
    """Concrete BlockBody container class owned by this fork."""

    block_header_class: type[SpecBlockHeaderType]
    """Concrete BlockHeader container class owned by this fork."""

    aggregated_attestations_class: type[SpecAggregatedAttestationsType]
    """Concrete AggregatedAttestations list class — block-body aggregated votes."""

    store_class: type[SpecStoreType]
    """Concrete forkchoice Store class owned by this fork."""

    attestation_data_class: type[SpecAttestationDataType]
    """Concrete AttestationData container class."""

    aggregated_attestation_class: type[SpecAggregatedAttestationType]
    """Concrete AggregatedAttestation container class."""

    config_class: type[SpecConfigType]
    """Concrete genesis Config container class."""

    @abstractmethod
    def generate_genesis(self, genesis_time: Uint64, validators: SSZList[Any]) -> SpecStateType:
        """Construct a genesis state for this fork."""

    @abstractmethod
    def create_store(
        self,
        state: SpecStateType,
        anchor_block: SpecBlockType,
        validator_id: ValidatorIndex | None,
    ) -> SpecStoreType:
        """Construct a forkchoice store anchored at the given state and block."""

    @abstractmethod
    def upgrade_state(self, state: SpecStateType) -> SpecStateType:
        """
        Migrate state from the previous fork's shape into this fork's shape.

        Every concrete fork must declare this explicitly. The root fork
        (previous is None) returns the input unchanged. Later forks return a
        state of their own shape derived from the predecessor's state.

        Making this abstract is intentional: a silent no-op default would
        hide missed migrations whenever a fork adds a field but forgets to
        override.
        """
