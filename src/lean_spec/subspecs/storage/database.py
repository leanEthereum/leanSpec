"""
Abstract database interface for consensus data storage.

Defines the Protocol that all database implementations must follow.
Uses structural subtyping for flexibility.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Protocol

from lean_spec.subspecs.containers import Block, Checkpoint, State
from lean_spec.subspecs.containers.attestation import AttestationData
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import Bytes32, Uint64


class Database(Protocol):
    """
    Protocol for consensus data storage.

    All database implementations must provide these methods.
    Uses structural subtyping - any class with matching methods satisfies the protocol.

    Storage Organization
    --------------------
    - Blocks: Indexed by block root hash
    - States: Indexed by associated block root hash (not state root)
    - Checkpoints: Justified and finalized tracking
    - Attestations: Latest attestation per validator
    - State root index: Maps state roots to block roots
    """

    # Block Operations

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

    # State Operations

    def get_state(self, root: Bytes32) -> State | None:
        """
        Retrieve a state by its associated block root.

        Args:
            root: Block root hash associated with this state.

        Returns:
            State if found, None otherwise.
        """
        ...

    def put_state(self, state: State, root: Bytes32) -> None:
        """
        Store a state indexed by its associated block root.

        Args:
            state: State to store.
            root: Block root hash associated with this state.
        """
        ...

    def has_state(self, root: Bytes32) -> bool:
        """
        Check if a state exists in storage.

        Args:
            root: Block root hash associated with the state.

        Returns:
            True if state exists.
        """
        ...

    # Checkpoint Operations

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

    # Attestation Operations

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

    # Head Tracking

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

    # Slot Index Operations

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

    # State Root Index Operations

    def get_block_root_by_state_root(self, state_root: Bytes32) -> Bytes32 | None:
        """
        Look up the block root associated with a state root.

        Needed for checkpoint sync and API endpoints that query by state root.

        Args:
            state_root: SSZ hash tree root of the state.

        Returns:
            Associated block root, or None if not indexed.
        """
        ...

    def put_block_root_by_state_root(self, state_root: Bytes32, block_root: Bytes32) -> None:
        """
        Index a block root by the state root it produced.

        Args:
            state_root: SSZ hash tree root of the post-state.
            block_root: Root of the block that produced this state.
        """
        ...

    # Genesis Time

    def get_genesis_time(self) -> Uint64 | None:
        """
        Retrieve the stored genesis time.

        Enables self-contained restarts without external genesis config.

        Returns:
            Genesis time as Unix timestamp, or None if not set.
        """
        ...

    def put_genesis_time(self, genesis_time: Uint64) -> None:
        """
        Store genesis time for future restarts.

        Args:
            genesis_time: Unix timestamp of genesis (slot 0).
        """
        ...

    # Transaction Control

    def commit(self) -> None:
        """
        Commit pending writes to durable storage.

        All writes via put_* methods are buffered until commit() or batch_write().
        Callers must explicitly commit after writes.
        """
        ...

    @contextmanager
    def batch_write(self) -> Generator[None]:
        """
        Context manager for atomic multi-write operations.

        All writes within the block are committed atomically on exit.
        Rolls back on exception to prevent partial writes.
        """
        ...

    # Pruning

    def prune_before_slot(self, slot: Slot, keep_roots: frozenset[Bytes32]) -> int:
        """
        Remove blocks and states with slots strictly before the given slot.

        Preserves entries whose roots are in keep_roots (e.g., the finalized block).
        Cleans up associated slot index entries.

        Args:
            slot: Prune entries with slots strictly below this value.
            keep_roots: Roots to preserve regardless of slot.

        Returns:
            Total number of entries pruned across all tables.
        """
        ...

    # Lifecycle

    def close(self) -> None:
        """Close database connection and release resources."""
        ...
