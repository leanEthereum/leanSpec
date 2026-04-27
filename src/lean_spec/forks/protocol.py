"""
Fork protocol interface for leanSpec consensus.

This module is deliberately agnostic of any individual devnet.
"""

from abc import ABC, abstractmethod
from typing import Any, ClassVar, Protocol, Self


class SpecStateType(Protocol):
    """Structural contract: any fork's State container class exposes genesis."""

    @classmethod
    def generate_genesis(cls, genesis_time: Any, validators: Any) -> Self:
        """Construct the fork's genesis state."""
        ...


class SpecStoreType(Protocol):
    """Structural contract: any fork's Store class exposes anchor construction."""

    @classmethod
    def from_anchor(cls, state: Any, anchor_block: Any, validator_id: Any) -> Self:
        """Construct a forkchoice store anchored at the given state/block."""
        ...


class ForkProtocol(ABC):
    """Identity and construction facade for a devnet fork."""

    NAME: ClassVar[str]
    """Fork name, e.g. 'lstar'. Must be unique across the registry."""

    VERSION: ClassVar[int]
    """Strictly monotonic version. Used to order forks in the registry."""

    NETWORK_NAME: ClassVar[str]
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

    state_class: ClassVar[type[SpecStateType]]
    """Concrete State container class owned by this fork."""

    block_class: ClassVar[type]
    """Concrete Block container class owned by this fork."""

    store_class: ClassVar[type[SpecStoreType]]
    """Concrete forkchoice Store class owned by this fork."""

    def generate_genesis(self, genesis_time: Any, validators: Any) -> Any:
        """Construct a genesis state using this fork's State class."""
        return self.state_class.generate_genesis(genesis_time, validators)

    def create_store(self, state: Any, anchor_block: Any, validator_id: Any) -> Any:
        """Construct a forkchoice store anchored at the given state and block."""
        return self.store_class.from_anchor(state, anchor_block, validator_id)

    @abstractmethod
    def upgrade_state(self, state: Any) -> Any:
        """
        Migrate state from the previous fork's shape into this fork's shape.

        Every concrete fork must declare this explicitly. The root fork
        (previous is None) returns the input unchanged. Later forks return a
        state of their own shape derived from the predecessor's state.

        Making this abstract is intentional: a silent no-op default would
        hide missed migrations whenever a fork adds a field but forgets to
        override.
        """
