"""Abstract database interface for consensus data storage."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Protocol

from lean_spec.spec.forks import Checkpoint, Slot
from lean_spec.spec.forks.protocol import (
    SpecBlockType,
    SpecStateType,
)
from lean_spec.spec.ssz import Bytes32, Uint64


class Database(Protocol):
    """
    Storage interface for consensus data.

    States are keyed by their associated block root, not their state root.
    """

    # Block Operations

    def get_block(self, root: Bytes32) -> SpecBlockType | None:
        """Retrieve a block by its root hash."""
        ...

    def put_block(self, block: SpecBlockType, root: Bytes32) -> None:
        """
        Store a block under its root hash.

        The caller passes the precomputed root to avoid recomputing it.
        """
        ...

    # State Operations

    def get_state(self, root: Bytes32) -> SpecStateType | None:
        """Retrieve a state by its associated block root."""
        ...

    def put_state(self, state: SpecStateType, root: Bytes32) -> None:
        """Store a state under its associated block root."""
        ...

    # Checkpoint Operations

    def get_justified_checkpoint(self) -> Checkpoint | None:
        """Retrieve the latest justified checkpoint, or None if unset."""
        ...

    def put_justified_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Store the latest justified checkpoint."""
        ...

    def get_finalized_checkpoint(self) -> Checkpoint | None:
        """Retrieve the latest finalized checkpoint, or None if unset."""
        ...

    def put_finalized_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Store the latest finalized checkpoint."""
        ...

    # Head Tracking

    def get_head_root(self) -> Bytes32 | None:
        """Retrieve the current head block root, or None if unset."""
        ...

    def put_head_root(self, root: Bytes32) -> None:
        """Store the current head block root."""
        ...

    # Slot Index Operations

    def get_block_root_by_slot(self, slot: Slot) -> Bytes32 | None:
        """Retrieve the canonical block root at a slot, or None if none."""
        ...

    def put_block_root_by_slot(self, slot: Slot, root: Bytes32) -> None:
        """Index a block root by its slot."""
        ...

    # State Root Index Operations

    def get_block_root_by_state_root(self, state_root: Bytes32) -> Bytes32 | None:
        """
        Look up the block root associated with a state root.

        Needed for checkpoint sync and queries that key on state root.
        """
        ...

    def put_block_root_by_state_root(self, state_root: Bytes32, block_root: Bytes32) -> None:
        """Index a block root by the state root it produced."""
        ...

    # Genesis Time

    def get_genesis_time(self) -> Uint64 | None:
        """
        Retrieve the stored genesis time, or None if unset.

        Persisting it lets the node restart without external genesis config.
        """
        ...

    def put_genesis_time(self, genesis_time: Uint64) -> None:
        """Store the genesis time as a Unix timestamp."""
        ...

    # Transaction Control

    @contextmanager
    def batch_write(self) -> Generator[None]:
        """
        Group writes into one atomic transaction.

        Commits on clean exit, rolls back on any exception.
        """
        ...

    # Pruning

    def prune_before_slot(self, slot: Slot, keep_roots: frozenset[Bytes32]) -> int:
        """
        Remove blocks and states with slots strictly below the given slot.

        Roots in the keep set survive regardless of slot.
        Associated slot-index and state-root-index entries are removed with them.
        Returns the total number of rows removed.
        """
        ...

    # Lifecycle

    def close(self) -> None:
        """Close database connection and release resources."""
        ...
