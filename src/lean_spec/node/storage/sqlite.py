"""
SQLite-backed persistent storage for consensus data.

All values are stored as SSZ-encoded bytes in BLOB columns.
Writes do not persist on their own.
Every write must run inside a batch-write block, which commits atomically on
exit and rolls back on error.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from lean_spec.node.storage.exceptions import (
    StorageCorruptionError,
    StorageReadError,
    StorageWriteError,
)
from lean_spec.node.storage.namespaces import (
    BLOCKS_CREATE_INDEX,
    BLOCKS_CREATE_TABLE,
    BLOCKS_TABLE_NAME,
    CHECKPOINTS_CREATE_TABLE,
    CHECKPOINTS_KEY_FINALIZED,
    CHECKPOINTS_KEY_GENESIS_TIME,
    CHECKPOINTS_KEY_HEAD,
    CHECKPOINTS_KEY_JUSTIFIED,
    CHECKPOINTS_TABLE_NAME,
    SLOT_INDEX_CREATE_TABLE,
    SLOT_INDEX_TABLE_NAME,
    STATE_ROOT_INDEX_CREATE_TABLE,
    STATE_ROOT_INDEX_TABLE_NAME,
    STATES_CREATE_INDEX,
    STATES_CREATE_TABLE,
    STATES_TABLE_NAME,
)
from lean_spec.spec.forks import Checkpoint, Slot
from lean_spec.spec.forks.protocol import (
    SpecBlockType,
    SpecStateType,
)
from lean_spec.spec.ssz import Bytes32, Uint64


class SQLiteDatabase:
    """
    SQLite-backed implementation of the storage interface.

    All access must come from a single writer on the node's event-loop thread.
    A shared connection with buffered writes is not safe for concurrent writers.
    """

    def __init__(
        self,
        path: Path | str,
        state_class: type[SpecStateType],
        block_class: type[SpecBlockType],
    ) -> None:
        """Open the database file (or ":memory:") and create tables if absent."""
        self._path = Path(path) if isinstance(path, str) else path
        self._state_class = state_class
        self._block_class = block_class

        # Disable the per-thread guard so a reader on another thread does not raise.
        # This grants no synchronization: writes must still come from one thread.
        self._connection = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
        )

        # Row factory enables access by column name: row["column_name"].
        self._connection.row_factory = sqlite3.Row

        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        cursor = self._connection.cursor()

        cursor.execute(BLOCKS_CREATE_TABLE)
        cursor.execute(BLOCKS_CREATE_INDEX)
        cursor.execute(STATES_CREATE_TABLE)
        cursor.execute(STATES_CREATE_INDEX)

        # Checkpoints are singletons, so a small key-value table suffices.
        cursor.execute(CHECKPOINTS_CREATE_TABLE)

        cursor.execute(SLOT_INDEX_CREATE_TABLE)
        cursor.execute(STATE_ROOT_INDEX_CREATE_TABLE)

        self._connection.commit()

    # Block Operations

    def get_block(self, root: Bytes32) -> SpecBlockType | None:
        """Retrieve a block by its root hash."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"SELECT data FROM {BLOCKS_TABLE_NAME} WHERE root = ?",
                (bytes(root),),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exception:
            raise StorageReadError(f"Failed to read block {root.hex()}: {exception}") from exception

        if row is None:
            return None

        try:
            return self._block_class.decode_bytes(row["data"])
        except Exception as exception:
            raise StorageCorruptionError(
                f"Corrupt block data for root {root.hex()}: {exception}"
            ) from exception

    def put_block(self, block: SpecBlockType, root: Bytes32) -> None:
        """Store a block with its root hash."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {BLOCKS_TABLE_NAME} (root, slot, data)
                VALUES (?, ?, ?)
                """,
                (bytes(root), int(block.slot), block.encode_bytes()),
            )
        except sqlite3.Error as exception:
            raise StorageWriteError(
                f"Failed to write block {root.hex()}: {exception}"
            ) from exception

    # State Operations

    def get_state(self, root: Bytes32) -> SpecStateType | None:
        """Retrieve a state by its associated block root."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"SELECT data FROM {STATES_TABLE_NAME} WHERE root = ?",
                (bytes(root),),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exception:
            raise StorageReadError(
                f"Failed to read state for block {root.hex()}: {exception}"
            ) from exception

        if row is None:
            return None

        try:
            return self._state_class.decode_bytes(row["data"])
        except Exception as exception:
            raise StorageCorruptionError(
                f"Corrupt state data for block root {root.hex()}: {exception}"
            ) from exception

    def put_state(self, state: SpecStateType, root: Bytes32) -> None:
        """Store a state indexed by its associated block root."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {STATES_TABLE_NAME} (root, slot, data)
                VALUES (?, ?, ?)
                """,
                (bytes(root), int(state.slot), state.encode_bytes()),
            )
        except sqlite3.Error as exception:
            raise StorageWriteError(
                f"Failed to write state for block {root.hex()}: {exception}"
            ) from exception

    # Checkpoint Operations

    def get_justified_checkpoint(self) -> Checkpoint | None:
        """Retrieve the latest justified checkpoint."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"SELECT data FROM {CHECKPOINTS_TABLE_NAME} WHERE key = ?",
                (CHECKPOINTS_KEY_JUSTIFIED,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exception:
            raise StorageReadError(
                f"Failed to read justified checkpoint: {exception}"
            ) from exception

        if row is None:
            return None

        try:
            return Checkpoint.decode_bytes(row["data"])
        except Exception as exception:
            raise StorageCorruptionError(
                f"Corrupt justified checkpoint data: {exception}"
            ) from exception

    def put_justified_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Store the latest justified checkpoint."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {CHECKPOINTS_TABLE_NAME} (key, data)
                VALUES (?, ?)
                """,
                (CHECKPOINTS_KEY_JUSTIFIED, checkpoint.encode_bytes()),
            )
        except sqlite3.Error as exception:
            raise StorageWriteError(
                f"Failed to write justified checkpoint: {exception}"
            ) from exception

    def get_finalized_checkpoint(self) -> Checkpoint | None:
        """Retrieve the latest finalized checkpoint."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"SELECT data FROM {CHECKPOINTS_TABLE_NAME} WHERE key = ?",
                (CHECKPOINTS_KEY_FINALIZED,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exception:
            raise StorageReadError(
                f"Failed to read finalized checkpoint: {exception}"
            ) from exception

        if row is None:
            return None

        try:
            return Checkpoint.decode_bytes(row["data"])
        except Exception as exception:
            raise StorageCorruptionError(
                f"Corrupt finalized checkpoint data: {exception}"
            ) from exception

    def put_finalized_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Store the latest finalized checkpoint."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {CHECKPOINTS_TABLE_NAME} (key, data)
                VALUES (?, ?)
                """,
                (CHECKPOINTS_KEY_FINALIZED, checkpoint.encode_bytes()),
            )
        except sqlite3.Error as exception:
            raise StorageWriteError(
                f"Failed to write finalized checkpoint: {exception}"
            ) from exception

    # Head Tracking

    def get_head_root(self) -> Bytes32 | None:
        """Retrieve the current head block root."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"SELECT data FROM {CHECKPOINTS_TABLE_NAME} WHERE key = ?",
                (CHECKPOINTS_KEY_HEAD,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exception:
            raise StorageReadError(f"Failed to read head root: {exception}") from exception

        if row is None:
            return None

        # Head is a raw 32-byte root, not an SSZ-encoded container.
        return Bytes32(row["data"])

    def put_head_root(self, root: Bytes32) -> None:
        """Store the current head block root."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {CHECKPOINTS_TABLE_NAME} (key, data)
                VALUES (?, ?)
                """,
                (CHECKPOINTS_KEY_HEAD, bytes(root)),
            )
        except sqlite3.Error as exception:
            raise StorageWriteError(f"Failed to write head root: {exception}") from exception

    # Slot Index Operations

    def get_block_root_by_slot(self, slot: Slot) -> Bytes32 | None:
        """Retrieve block root for a specific slot."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"SELECT root FROM {SLOT_INDEX_TABLE_NAME} WHERE slot = ?",
                (int(slot),),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exception:
            raise StorageReadError(
                f"Failed to read block root for slot {slot}: {exception}"
            ) from exception

        if row is None:
            return None
        return Bytes32(row["root"])

    def put_block_root_by_slot(self, slot: Slot, root: Bytes32) -> None:
        """Index a block root by its slot."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {SLOT_INDEX_TABLE_NAME} (slot, root)
                VALUES (?, ?)
                """,
                (int(slot), bytes(root)),
            )
        except sqlite3.Error as exception:
            raise StorageWriteError(
                f"Failed to write slot index for slot {slot}: {exception}"
            ) from exception

    # State Root Index Operations

    def get_block_root_by_state_root(self, state_root: Bytes32) -> Bytes32 | None:
        """Look up the block root associated with a state root."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"SELECT block_root FROM {STATE_ROOT_INDEX_TABLE_NAME} WHERE state_root = ?",
                (bytes(state_root),),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exception:
            raise StorageReadError(
                f"Failed to read block root for state root {state_root.hex()}: {exception}"
            ) from exception

        if row is None:
            return None
        return Bytes32(row["block_root"])

    def put_block_root_by_state_root(self, state_root: Bytes32, block_root: Bytes32) -> None:
        """Index a block root by the state root it produced."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {STATE_ROOT_INDEX_TABLE_NAME} (state_root, block_root)
                VALUES (?, ?)
                """,
                (bytes(state_root), bytes(block_root)),
            )
        except sqlite3.Error as exception:
            raise StorageWriteError(
                f"Failed to write state root index {state_root.hex()}: {exception}"
            ) from exception

    # Genesis Time

    def get_genesis_time(self) -> Uint64 | None:
        """Retrieve the stored genesis time."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"SELECT data FROM {CHECKPOINTS_TABLE_NAME} WHERE key = ?",
                (CHECKPOINTS_KEY_GENESIS_TIME,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exception:
            raise StorageReadError(f"Failed to read genesis time: {exception}") from exception

        if row is None:
            return None

        # Genesis time is stored as an 8-byte little-endian integer.
        return Uint64(int.from_bytes(row["data"], byteorder="little"))

    def put_genesis_time(self, genesis_time: Uint64) -> None:
        """Store genesis time for future restarts."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {CHECKPOINTS_TABLE_NAME} (key, data)
                VALUES (?, ?)
                """,
                (CHECKPOINTS_KEY_GENESIS_TIME, int(genesis_time).to_bytes(8, byteorder="little")),
            )
        except sqlite3.Error as exception:
            raise StorageWriteError(f"Failed to write genesis time: {exception}") from exception

    # Transaction Control

    @contextmanager
    def batch_write(self) -> Generator[None]:
        """
        Group writes into one atomic transaction.

        Commits on clean exit, rolls back on any exception.
        """
        try:
            yield
            self._connection.commit()
        except (StorageWriteError, StorageCorruptionError):
            self._connection.rollback()
            raise
        except sqlite3.Error as exception:
            self._connection.rollback()
            raise StorageWriteError(f"Batch write failed: {exception}") from exception
        except BaseException:
            self._connection.rollback()
            raise

    # Pruning

    def prune_before_slot(self, slot: Slot, keep_roots: frozenset[Bytes32]) -> int:
        """
        Remove blocks and states with slots strictly below the given slot.

        Roots in the keep set survive regardless of slot.
        Associated slot-index and state-root-index entries are removed with them.
        Returns the total number of rows removed.
        """
        try:
            cursor = self._connection.cursor()
            total_pruned = 0

            keep_root_bytes = [bytes(root) for root in keep_roots]
            placeholders = ",".join("?" for _ in keep_root_bytes)

            def prune_table_below_slot(table_name: str) -> int:
                # An empty keep set omits the NOT IN clause to avoid invalid empty parentheses.
                if keep_root_bytes:
                    cursor.execute(
                        f"DELETE FROM {table_name} WHERE slot < ? AND root NOT IN ({placeholders})",
                        [int(slot), *keep_root_bytes],
                    )
                else:
                    cursor.execute(
                        f"DELETE FROM {table_name} WHERE slot < ?",
                        (int(slot),),
                    )
                return cursor.rowcount

            # Blocks, states, and the slot index all carry root and slot columns,
            # so the same keep-aware delete prunes each of them.
            total_pruned += prune_table_below_slot(BLOCKS_TABLE_NAME)
            total_pruned += prune_table_below_slot(STATES_TABLE_NAME)
            total_pruned += prune_table_below_slot(SLOT_INDEX_TABLE_NAME)

            # The state root index has no slot column, so drop the entries that
            # now point at blocks no longer present.
            cursor.execute(
                f"""
                DELETE FROM {STATE_ROOT_INDEX_TABLE_NAME}
                WHERE block_root NOT IN (SELECT root FROM {BLOCKS_TABLE_NAME})
                """
            )
            total_pruned += cursor.rowcount

            return total_pruned
        except sqlite3.Error as exception:
            raise StorageWriteError(
                f"Failed to prune before slot {slot}: {exception}"
            ) from exception

    # Lifecycle

    def close(self) -> None:
        """Close database connection."""
        self._connection.close()

    def __enter__(self) -> SQLiteDatabase:
        """Context manager entry."""
        return self

    def __exit__(self, *args: object) -> None:
        """Context manager exit."""
        self.close()
