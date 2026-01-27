"""
Abstract database interface for consensus data storage.

Defines the Protocol that all database implementations must follow.
Uses structural subtyping for flexibility.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from lean_spec.subspecs.containers import Block, Checkpoint, State
    from lean_spec.subspecs.containers.attestation import AttestationData
    from lean_spec.subspecs.containers.slot import Slot
    from lean_spec.subspecs.containers.validator import ValidatorIndex
    from lean_spec.types import Bytes32


class Database(Protocol):
    """
    Protocol for consensus data storage.

    All database implementations must provide these methods.
    Uses structural subtyping - any class with matching methods satisfies the protocol.

    Storage Organization
    --------------------
    - Blocks: Indexed by root hash
    - States: Indexed by root hash
    - Checkpoints: Justified and finalized tracking
    - Attestations: Latest attestation per validator
    """

    # -------------------------------------------------------------------------
    # Block Operations
    # -------------------------------------------------------------------------

    def get_block(self, root: Bytes32) -> Block | None:
        """
        Retrieve a block by its root hash.

        Args:
            root: SSZ hash tree root of the block.

        Returns:
            Block if found, None otherwise.
        """
        ...

    def put_block(self, block: Block, root: Bytes32) -> None:
        """
        Store a block with its root hash.

        Args:
            block: Block to store.
            root: Pre-computed root hash (avoids recomputation).
        """
        ...

    def has_block(self, root: Bytes32) -> bool:
        """
        Check if a block exists in storage.

        Args:
            root: SSZ hash tree root of the block.

        Returns:
            True if block exists.
        """
        ...

    # -------------------------------------------------------------------------
    # State Operations
    # -------------------------------------------------------------------------

    def get_state(self, root: Bytes32) -> State | None:
        """
        Retrieve a state by its root hash.

        Args:
            root: SSZ hash tree root of the state.

        Returns:
            State if found, None otherwise.
        """
        ...

    def put_state(self, state: State, root: Bytes32) -> None:
        """
        Store a state with its root hash.

        Args:
            state: State to store.
            root: Pre-computed root hash (avoids recomputation).
        """
        ...

    def has_state(self, root: Bytes32) -> bool:
        """
        Check if a state exists in storage.

        Args:
            root: SSZ hash tree root of the state.

        Returns:
            True if state exists.
        """
        ...

    # -------------------------------------------------------------------------
    # Checkpoint Operations
    # -------------------------------------------------------------------------

    def get_justified_checkpoint(self) -> Checkpoint | None:
        """
        Retrieve the latest justified checkpoint.

        Returns:
            Latest justified checkpoint, or None if not set.
        """
        ...

    def put_justified_checkpoint(self, checkpoint: Checkpoint) -> None:
        """
        Store the latest justified checkpoint.

        Args:
            checkpoint: New justified checkpoint.
        """
        ...

    def get_finalized_checkpoint(self) -> Checkpoint | None:
        """
        Retrieve the latest finalized checkpoint.

        Returns:
            Latest finalized checkpoint, or None if not set.
        """
        ...

    def put_finalized_checkpoint(self, checkpoint: Checkpoint) -> None:
        """
        Store the latest finalized checkpoint.

        Args:
            checkpoint: New finalized checkpoint.
        """
        ...

    # -------------------------------------------------------------------------
    # Attestation Operations
    # -------------------------------------------------------------------------

    def get_latest_attestation(self, validator_index: ValidatorIndex) -> AttestationData | None:
        """
        Retrieve the latest attestation for a validator.

        Args:
            validator_index: Index of the validator.

        Returns:
            Latest attestation data, or None if not found.
        """
        ...

    def put_latest_attestation(
        self,
        validator_index: ValidatorIndex,
        attestation: AttestationData,
    ) -> None:
        """
        Store the latest attestation for a validator.

        Args:
            validator_index: Index of the validator.
            attestation: Attestation data to store.
        """
        ...

    def get_all_latest_attestations(self) -> dict[ValidatorIndex, AttestationData]:
        """
        Retrieve all latest attestations.

        Returns:
            Mapping from validator index to attestation data.
        """
        ...

    # -------------------------------------------------------------------------
    # Head Tracking
    # -------------------------------------------------------------------------

    def get_head_root(self) -> Bytes32 | None:
        """
        Retrieve the current head block root.

        Returns:
            Head block root, or None if not set.
        """
        ...

    def put_head_root(self, root: Bytes32) -> None:
        """
        Store the current head block root.

        Args:
            root: New head block root.
        """
        ...

    # -------------------------------------------------------------------------
    # Slot Index Operations
    # -------------------------------------------------------------------------

    def get_block_root_by_slot(self, slot: Slot) -> Bytes32 | None:
        """
        Retrieve block root for a specific slot.

        Args:
            slot: Slot number to look up.

        Returns:
            Block root at that slot, or None if no block.
        """
        ...

    def put_block_root_by_slot(self, slot: Slot, root: Bytes32) -> None:
        """
        Index a block root by its slot.

        Args:
            slot: Slot of the block.
            root: Root hash of the block.
        """
        ...

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def close(self) -> None:
        """Close database connection and release resources."""
        ...
