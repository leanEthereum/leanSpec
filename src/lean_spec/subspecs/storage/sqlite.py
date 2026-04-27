"""
SQLite database implementation for consensus data storage.

This module provides persistent storage for Ethereum consensus data:

- Blocks and states indexed by their SSZ root hash
- Checkpoints for tracking justification and finalization
- Attestations indexed by validator
- Slot-to-root mappings for historical queries
- State root to block root index for checkpoint sync

All data is stored as SSZ-encoded bytes in BLOB columns.
The SSZ format ensures deterministic serialization across implementations.

Writes are not auto-committed. Callers must use batch_write() for multi-write
atomicity or commit() for single-write durability.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from lean_spec.forks import State
from lean_spec.forks.lstar.containers import Block, Checkpoint, ValidatorIndex
from lean_spec.forks.lstar.containers.attestation import AttestationData
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.types import Bytes32, Uint64

from .exceptions import StorageCorruptionError, StorageReadError, StorageWriteError
from .namespaces import (
    ATTESTATIONS,
    BLOCKS,
    CHECKPOINTS,
    SLOT_INDEX,
    STATE_ROOT_INDEX,
    STATES,
)


class SQLiteDatabase:
    """
    SQLite implementation of the Database protocol.

    Stores consensus data in a single SQLite file.
    Thread-safe through SQLite's built-in locking.

    Data is stored as SSZ-encoded bytes.
    Deserialization happens on read.

    Writes are buffered until explicitly committed via commit() or batch_write().
    """

    def __init__(self, path: Path | str, state_class: type[State] = State) -> None:
        """
        Initialize SQLite database.

        Creates database file and tables if they don't exist.

        Args:
            path: Path to SQLite database file.
                  Use ":memory:" for in-memory database.
            state_class: State class used to decode SSZ bytes.
        """
        self._path = Path(path) if isinstance(path, str) else path
        self._state_class = state_class

        # SQLite handles concurrent access through file-level locking.
        #
        # The check_same_thread=False flag allows multiple threads to share
        # this connection. SQLite serializes writes internally.
        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
        )

        # Row factory enables dict-like access: row["column_name"].
        #
        # This makes the code more readable than tuple indexing.
        self._conn.row_factory = sqlite3.Row

        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        cursor = self._conn.cursor()

        # Block and state tables use root hash as primary key.
        #
        # This matches how consensus clients identify data: by SSZ merkle root.
        # The slot index enables efficient range queries for historical data.
        cursor.execute(BLOCKS.CREATE_TABLE)
        cursor.execute(BLOCKS.CREATE_INDEX)
        cursor.execute(STATES.CREATE_TABLE)
        cursor.execute(STATES.CREATE_INDEX)

        # Checkpoints use a key-value pattern for singleton values.
        #
        # Only one justified and one finalized checkpoint exist at any time.
        cursor.execute(CHECKPOINTS.CREATE_TABLE)

        # Attestations are indexed by validator.
        #
        # Fork choice needs the latest attestation from each validator
        # to compute the canonical head.
        cursor.execute(ATTESTATIONS.CREATE_TABLE)

        # Slot index maps slot numbers to block roots.
        #
        # Enables queries like "what block was at slot N?"
        cursor.execute(SLOT_INDEX.CREATE_TABLE)

        # State root index maps state roots to block roots.
        #
        # Needed for checkpoint sync and API endpoints that query by state root.
        cursor.execute(STATE_ROOT_INDEX.CREATE_TABLE)

        self._conn.commit()

    # Block Operations

    def get_block(self, root: Bytes32) -> Block | None:
        """Retrieve a block by its root hash."""
        try:
            cursor = self._conn.cursor()

            # Query by root hash, the canonical identifier in consensus.
            #
            # The root is the SSZ merkle root of the block.
            # This 32-byte hash uniquely identifies the block content.
            cursor.execute(
                f"SELECT data FROM {BLOCKS.TABLE_NAME} WHERE root = ?",
                (bytes(root),),
            )
            row = cursor.fetchone()
        except sqlite3.Error as e:
            raise StorageReadError(f"Failed to read block {root.hex()}: {e}") from e

        if row is None:
            return None

        try:
            return Block.decode_bytes(row["data"])
        except Exception as e:
            raise StorageCorruptionError(f"Corrupt block data for root {root.hex()}: {e}") from e

    def put_block(self, block: Block, root: Bytes32) -> None:
        """Store a block with its root hash."""
        try:
            cursor = self._conn.cursor()

            # INSERT OR REPLACE handles both new blocks and updates.
            #
            # While blocks should be immutable (same root = same content),
            # this pattern simplifies the code without correctness issues.
            # The slot column enables efficient historical range queries.
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {BLOCKS.TABLE_NAME} (root, slot, data)
                VALUES (?, ?, ?)
                """,
                (bytes(root), int(block.slot), block.encode_bytes()),
            )
        except sqlite3.Error as e:
            raise StorageWriteError(f"Failed to write block {root.hex()}: {e}") from e

    def has_block(self, root: Bytes32) -> bool:
        """Check if a block exists in storage."""
        try:
            cursor = self._conn.cursor()

            # SELECT 1 is an existence check optimization.
            #
            # We only care whether a row exists, not its contents.
            # This avoids deserializing potentially large SSZ data.
            cursor.execute(
                f"SELECT 1 FROM {BLOCKS.TABLE_NAME} WHERE root = ?",
                (bytes(root),),
            )
            return cursor.fetchone() is not None
        except sqlite3.Error as e:
            raise StorageReadError(f"Failed to check block existence {root.hex()}: {e}") from e

    # State Operations

    #
    # States are the full beacon chain state at a given slot.
    # They are large (~2MB+) and expensive to compute from scratch.
    # Storing states enables fast re-initialization and historical queries.

    def get_state(self, root: Bytes32) -> State | None:
        """Retrieve a state by its associated block root."""
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"SELECT data FROM {STATES.TABLE_NAME} WHERE root = ?",
                (bytes(root),),
            )
            row = cursor.fetchone()
        except sqlite3.Error as e:
            raise StorageReadError(f"Failed to read state for block {root.hex()}: {e}") from e

        if row is None:
            return None

        try:
            return self._state_class.decode_bytes(row["data"])
        except Exception as e:
            raise StorageCorruptionError(
                f"Corrupt state data for block root {root.hex()}: {e}"
            ) from e

    def put_state(self, state: State, root: Bytes32) -> None:
        """Store a state indexed by its associated block root."""
        try:
            cursor = self._conn.cursor()

            # States should be stored at epoch boundaries for efficient access.
            #
            # Clients typically store one state per epoch to balance
            # storage costs against replay costs for intermediate slots.
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {STATES.TABLE_NAME} (root, slot, data)
                VALUES (?, ?, ?)
                """,
                (bytes(root), int(state.slot), state.encode_bytes()),
            )
        except sqlite3.Error as e:
            raise StorageWriteError(f"Failed to write state for block {root.hex()}: {e}") from e

    def has_state(self, root: Bytes32) -> bool:
        """Check if a state exists in storage."""
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"SELECT 1 FROM {STATES.TABLE_NAME} WHERE root = ?",
                (bytes(root),),
            )
            return cursor.fetchone() is not None
        except sqlite3.Error as e:
            raise StorageReadError(
                f"Failed to check state existence for block {root.hex()}: {e}"
            ) from e

    # Checkpoint Operations

    #
    # Checkpoints mark finality progress in the consensus protocol.
    # Justified checkpoints have 2/3 validator support.
    # Finalized checkpoints are irreversible - blocks before them never reorg.

    def get_justified_checkpoint(self) -> Checkpoint | None:
        """Retrieve the latest justified checkpoint."""
        try:
            cursor = self._conn.cursor()

            # Justified checkpoint: has received 2/3 attestation weight.
            #
            # This checkpoint may still be reverted if a competing
            # checkpoint gains more support. Not yet final.
            cursor.execute(
                f"SELECT data FROM {CHECKPOINTS.TABLE_NAME} WHERE key = ?",
                (CHECKPOINTS.KEY_JUSTIFIED,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as e:
            raise StorageReadError(f"Failed to read justified checkpoint: {e}") from e

        if row is None:
            return None

        try:
            return Checkpoint.decode_bytes(row["data"])
        except Exception as e:
            raise StorageCorruptionError(f"Corrupt justified checkpoint data: {e}") from e

    def put_justified_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Store the latest justified checkpoint."""
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {CHECKPOINTS.TABLE_NAME} (key, data)
                VALUES (?, ?)
                """,
                (CHECKPOINTS.KEY_JUSTIFIED, checkpoint.encode_bytes()),
            )
        except sqlite3.Error as e:
            raise StorageWriteError(f"Failed to write justified checkpoint: {e}") from e

    def get_finalized_checkpoint(self) -> Checkpoint | None:
        """Retrieve the latest finalized checkpoint."""
        try:
            cursor = self._conn.cursor()

            # Finalized checkpoint: irreversible under normal operation.
            #
            # Once finalized, all blocks in the checkpoint's chain are permanent.
            # Reorging past finality requires 1/3 validators to be slashed.
            cursor.execute(
                f"SELECT data FROM {CHECKPOINTS.TABLE_NAME} WHERE key = ?",
                (CHECKPOINTS.KEY_FINALIZED,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as e:
            raise StorageReadError(f"Failed to read finalized checkpoint: {e}") from e

        if row is None:
            return None

        try:
            return Checkpoint.decode_bytes(row["data"])
        except Exception as e:
            raise StorageCorruptionError(f"Corrupt finalized checkpoint data: {e}") from e

    def put_finalized_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Store the latest finalized checkpoint."""
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {CHECKPOINTS.TABLE_NAME} (key, data)
                VALUES (?, ?)
                """,
                (CHECKPOINTS.KEY_FINALIZED, checkpoint.encode_bytes()),
            )
        except sqlite3.Error as e:
            raise StorageWriteError(f"Failed to write finalized checkpoint: {e}") from e

    # Attestation Operations

    #
    # Attestations are validator votes on the canonical chain.
    # Fork choice uses the latest attestation from each validator
    # to determine which branch has the most support.

    def get_latest_attestation(self, validator_index: ValidatorIndex) -> AttestationData | None:
        """Retrieve the latest attestation for a validator."""
        try:
            cursor = self._conn.cursor()

            # Only the latest attestation matters for fork choice.
            #
            # Each validator has at most one entry.
            # Newer attestations replace older ones.
            cursor.execute(
                f"SELECT data FROM {ATTESTATIONS.TABLE_NAME} WHERE validator_index = ?",
                (int(validator_index),),
            )
            row = cursor.fetchone()
        except sqlite3.Error as e:
            raise StorageReadError(
                f"Failed to read attestation for validator {validator_index}: {e}"
            ) from e

        if row is None:
            return None

        try:
            return AttestationData.decode_bytes(row["data"])
        except Exception as e:
            raise StorageCorruptionError(
                f"Corrupt attestation data for validator {validator_index}: {e}"
            ) from e

    def put_latest_attestation(
        self,
        validator_index: ValidatorIndex,
        attestation: AttestationData,
    ) -> None:
        """Store the latest attestation for a validator."""
        try:
            cursor = self._conn.cursor()

            # INSERT OR REPLACE ensures we keep only the newest attestation.
            #
            # The validator_index is the primary key.
            # This naturally enforces the "latest only" invariant.
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {ATTESTATIONS.TABLE_NAME} (validator_index, data)
                VALUES (?, ?)
                """,
                (int(validator_index), attestation.encode_bytes()),
            )
        except sqlite3.Error as e:
            raise StorageWriteError(
                f"Failed to write attestation for validator {validator_index}: {e}"
            ) from e

    def get_all_latest_attestations(self) -> dict[ValidatorIndex, AttestationData]:
        """Retrieve all latest attestations."""
        try:
            cursor = self._conn.cursor()

            # Load all attestations for fork choice computation.
            #
            # This can be a large result set (hundreds of thousands of validators).
            # Consider streaming or batching for production use.
            cursor.execute(f"SELECT validator_index, data FROM {ATTESTATIONS.TABLE_NAME}")
            rows = cursor.fetchall()
        except sqlite3.Error as e:
            raise StorageReadError(f"Failed to read all attestations: {e}") from e

        try:
            return {
                ValidatorIndex(row["validator_index"]): AttestationData.decode_bytes(row["data"])
                for row in rows
            }
        except Exception as e:
            raise StorageCorruptionError(f"Corrupt attestation data: {e}") from e

    # Head Tracking

    #
    # The head is the tip of the canonical chain as determined by fork choice.
    # This is a singleton value that changes as new blocks arrive.

    def get_head_root(self) -> Bytes32 | None:
        """Retrieve the current head block root."""
        try:
            cursor = self._conn.cursor()

            # The head root identifies the current best block.
            #
            # Fork choice updates this after processing each new block.
            # Stored in the checkpoints table as a special singleton key.
            cursor.execute(
                f"SELECT data FROM {CHECKPOINTS.TABLE_NAME} WHERE key = ?",
                (CHECKPOINTS.KEY_HEAD,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as e:
            raise StorageReadError(f"Failed to read head root: {e}") from e

        if row is None:
            return None

        # Head is a raw 32-byte root, not an SSZ-encoded container.
        return Bytes32(row["data"])

    def put_head_root(self, root: Bytes32) -> None:
        """Store the current head block root."""
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {CHECKPOINTS.TABLE_NAME} (key, data)
                VALUES (?, ?)
                """,
                (CHECKPOINTS.KEY_HEAD, bytes(root)),
            )
        except sqlite3.Error as e:
            raise StorageWriteError(f"Failed to write head root: {e}") from e

    # Slot Index Operations

    #
    # Slots are time intervals.
    # This index maps slot numbers to blocks, enabling historical queries.
    # Note: not every slot has a block (missed slots happen).

    def get_block_root_by_slot(self, slot: Slot) -> Bytes32 | None:
        """Retrieve block root for a specific slot."""
        try:
            cursor = self._conn.cursor()

            # Returns the canonical block at this slot.
            #
            # A slot may have no block (proposer missed their turn).
            # A slot may have had multiple competing blocks (only one is canonical).
            cursor.execute(
                f"SELECT root FROM {SLOT_INDEX.TABLE_NAME} WHERE slot = ?",
                (int(slot),),
            )
            row = cursor.fetchone()
        except sqlite3.Error as e:
            raise StorageReadError(f"Failed to read block root for slot {slot}: {e}") from e

        if row is None:
            return None
        return Bytes32(row["root"])

    def put_block_root_by_slot(self, slot: Slot, root: Bytes32) -> None:
        """Index a block root by its slot."""
        try:
            cursor = self._conn.cursor()

            # Updates as the canonical chain changes.
            #
            # During reorgs, the same slot may point to different blocks
            # at different times. This always reflects the current canonical chain.
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {SLOT_INDEX.TABLE_NAME} (slot, root)
                VALUES (?, ?)
                """,
                (int(slot), bytes(root)),
            )
        except sqlite3.Error as e:
            raise StorageWriteError(f"Failed to write slot index for slot {slot}: {e}") from e

    # State Root Index Operations

    #
    # Maps state roots to block roots.
    # Both ream (Rust) and zeam (Zig) maintain this index.
    # Needed for checkpoint sync and API endpoints that query by state root.

    def get_block_root_by_state_root(self, state_root: Bytes32) -> Bytes32 | None:
        """Look up the block root associated with a state root."""
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"SELECT block_root FROM {STATE_ROOT_INDEX.TABLE_NAME} WHERE state_root = ?",
                (bytes(state_root),),
            )
            row = cursor.fetchone()
        except sqlite3.Error as e:
            raise StorageReadError(
                f"Failed to read block root for state root {state_root.hex()}: {e}"
            ) from e

        if row is None:
            return None
        return Bytes32(row["block_root"])

    def put_block_root_by_state_root(self, state_root: Bytes32, block_root: Bytes32) -> None:
        """Index a block root by the state root it produced."""
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {STATE_ROOT_INDEX.TABLE_NAME} (state_root, block_root)
                VALUES (?, ?)
                """,
                (bytes(state_root), bytes(block_root)),
            )
        except sqlite3.Error as e:
            raise StorageWriteError(
                f"Failed to write state root index {state_root.hex()}: {e}"
            ) from e

    # Genesis Time

    #
    # Storing genesis time in the database enables self-contained restarts.
    # Without it, the node needs external configuration to know when genesis was.

    def get_genesis_time(self) -> Uint64 | None:
        """Retrieve the stored genesis time."""
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"SELECT data FROM {CHECKPOINTS.TABLE_NAME} WHERE key = ?",
                (CHECKPOINTS.KEY_GENESIS_TIME,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as e:
            raise StorageReadError(f"Failed to read genesis time: {e}") from e

        if row is None:
            return None

        # Genesis time is stored as 8-byte little-endian integer.
        return Uint64(int.from_bytes(row["data"], byteorder="little"))

    def put_genesis_time(self, genesis_time: Uint64) -> None:
        """Store genesis time for future restarts."""
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {CHECKPOINTS.TABLE_NAME} (key, data)
                VALUES (?, ?)
                """,
                (CHECKPOINTS.KEY_GENESIS_TIME, int(genesis_time).to_bytes(8, byteorder="little")),
            )
        except sqlite3.Error as e:
            raise StorageWriteError(f"Failed to write genesis time: {e}") from e

    # Transaction Control

    def commit(self) -> None:
        """Commit pending writes to durable storage."""
        try:
            self._conn.commit()
        except sqlite3.Error as e:
            raise StorageWriteError(f"Failed to commit: {e}") from e

    @contextmanager
    def batch_write(self) -> Generator[None]:
        """
        Context manager for atomic multi-write operations.

        All writes within the block are committed atomically on exit.
        Rolls back on exception to prevent partial writes.
        """
        try:
            yield
            self._conn.commit()
        except (StorageWriteError, StorageCorruptionError):
            self._conn.rollback()
            raise
        except sqlite3.Error as e:
            self._conn.rollback()
            raise StorageWriteError(f"Batch write failed: {e}") from e
        except BaseException:
            self._conn.rollback()
            raise

    # Pruning

    #
    # When finalization advances, blocks/states before the finalized slot
    # can be removed. Both ream (Rust) and zeam (Zig) implement pruning.

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
        try:
            cursor = self._conn.cursor()
            total_pruned = 0

            # Build the exclusion set for parameterized queries.
            keep_bytes = [bytes(r) for r in keep_roots]
            placeholders = ",".join("?" for _ in keep_bytes)

            # Prune blocks below the threshold, preserving kept roots.
            if keep_bytes:
                cursor.execute(
                    f"DELETE FROM {BLOCKS.TABLE_NAME} "
                    f"WHERE slot < ? AND root NOT IN ({placeholders})",
                    [int(slot), *keep_bytes],
                )
            else:
                cursor.execute(
                    f"DELETE FROM {BLOCKS.TABLE_NAME} WHERE slot < ?",
                    (int(slot),),
                )
            total_pruned += cursor.rowcount

            # Prune states below the threshold, preserving kept roots.
            if keep_bytes:
                cursor.execute(
                    f"DELETE FROM {STATES.TABLE_NAME} "
                    f"WHERE slot < ? AND root NOT IN ({placeholders})",
                    [int(slot), *keep_bytes],
                )
            else:
                cursor.execute(
                    f"DELETE FROM {STATES.TABLE_NAME} WHERE slot < ?",
                    (int(slot),),
                )
            total_pruned += cursor.rowcount

            # Prune slot index entries below the threshold.
            cursor.execute(
                f"DELETE FROM {SLOT_INDEX.TABLE_NAME} WHERE slot < ?",
                (int(slot),),
            )
            total_pruned += cursor.rowcount

            return total_pruned
        except sqlite3.Error as e:
            raise StorageWriteError(f"Failed to prune before slot {slot}: {e}") from e

    # Lifecycle

    #
    # SQLite connections should be explicitly closed when done.
    # The context manager pattern ensures cleanup even on exceptions.

    def close(self) -> None:
        """Close database connection."""
        self._conn.close()

    def __enter__(self) -> SQLiteDatabase:
        """Context manager entry."""
        return self

    def __exit__(self, *args: object) -> None:
        """Context manager exit."""
        self.close()
