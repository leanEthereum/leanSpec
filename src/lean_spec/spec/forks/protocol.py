"""
Fork protocol interface for leanSpec consensus.

This module is deliberately agnostic of any individual devnet.
"""

from __future__ import annotations

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


class SpecStateType(SpecSSZType, Protocol):
    """Structural contract: any fork's State container class exposes genesis."""

    @property
    def slot(self) -> Slot:
        """Current slot of this state."""
        ...

    @property
    def config(self) -> SpecSSZType:
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


class SpecStoreType(Protocol):
    """
    Structural contract: any fork's forkchoice Store.

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
    def validator_index(self) -> ValidatorIndex | None:
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

    state_class: type[SpecStateType]
    """Concrete State container class owned by this fork."""

    block_class: type[SpecBlockType]
    """Concrete Block container class owned by this fork."""

    block_body_class: type[SpecSSZType]
    """Concrete BlockBody container class owned by this fork."""

    block_header_class: type[SpecSSZType]
    """Concrete BlockHeader container class owned by this fork."""

    aggregated_attestations_class: type[SpecSSZType]
    """Concrete AggregatedAttestations list class — block-body aggregated votes."""

    store_class: type[SpecStoreType]
    """Concrete forkchoice Store class owned by this fork."""

    attestation_data_class: type[SpecSSZType]
    """Concrete AttestationData container class."""

    aggregated_attestation_class: type[SpecSSZType]
    """Concrete AggregatedAttestation container class."""

    genesis_config_class: type[SpecSSZType]
    """Concrete genesis configuration container class."""

    @abstractmethod
    def generate_genesis(self, genesis_time: Uint64, validators: SSZList[Any]) -> SpecStateType:
        """Construct a genesis state for this fork."""

    @abstractmethod
    def create_store(
        self,
        state: SpecStateType,
        anchor_block: SpecBlockType,
        validator_index: ValidatorIndex | None,
    ) -> SpecStoreType:
        """Construct a forkchoice store anchored at the given state and block."""
