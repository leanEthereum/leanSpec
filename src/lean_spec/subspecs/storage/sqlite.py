"""
SQLite database implementation for consensus data storage.

This module provides persistent storage for Ethereum consensus data:

- Blocks and states indexed by their SSZ root hash
- Checkpoints for tracking justification and finalization
- Attestations indexed by validator
- Slot-to-root mappings for historical queries

All data is stored as SSZ-encoded bytes in BLOB columns.
The SSZ format ensures deterministic serialization across implementations.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

from lean_spec.subspecs.containers import Block, Checkpoint, State, ValidatorIndex
from lean_spec.subspecs.containers.attestation import AttestationData
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32

from .namespaces import (
    ATTESTATIONS,
    BLOCKS,
    CHECKPOINTS,
    SLOT_INDEX,
    STATES,
)

if TYPE_CHECKING:
    pass


class SQLiteDatabase:
    """
    SQLite implementation of the Database protocol.

    Stores consensus data in a single SQLite file.
    Thread-safe through SQLite's built-in locking.

    Data is stored as SSZ-encoded bytes.
    Deserialization happens on read.
    """

    def __init__(self, path: Path | str) -> None:
        """
        Initialize SQLite database.

        Creates database file and tables if they don't exist.

        Args:
            path: Path to SQLite database file.
                  Use ":memory:" for in-memory database.
        """
        self._path = Path(path) if isinstance(path, str) else path

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

        self._conn.commit()

    # -------------------------------------------------------------------------
    # Block Operations
    # -------------------------------------------------------------------------

    def get_block(self, root: Bytes32) -> Block | None:
        """Retrieve a block by its root hash."""
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
        if row is None:
            return None

        # Deserialize from SSZ bytes stored in the database.
        return Block.decode_bytes(row["data"])

    def put_block(self, block: Block, root: Bytes32) -> None:
        """Store a block with its root hash."""
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

        # Commit immediately to ensure durability.
        #
        # Each write is atomic. Callers can rely on data being persisted
        # after this returns.
        self._conn.commit()

    def has_block(self, root: Bytes32) -> bool:
        """Check if a block exists in storage."""
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

    # -------------------------------------------------------------------------
    # State Operations
    # -------------------------------------------------------------------------
    #
    # States are the full beacon chain state at a given slot.
    # They are large (~2MB+) and expensive to compute from scratch.
    # Storing states enables fast re-initialization and historical queries.

    def get_state(self, root: Bytes32) -> State | None:
        """Retrieve a state by its root hash."""
        cursor = self._conn.cursor()
        cursor.execute(
            f"SELECT data FROM {STATES.TABLE_NAME} WHERE root = ?",
            (bytes(root),),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        # State deserialization is expensive.
        #
        # Consider caching frequently accessed states in memory.
        return State.decode_bytes(row["data"])

    def put_state(self, state: State, root: Bytes32) -> None:
        """Store a state with its root hash."""
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
        self._conn.commit()

    def has_state(self, root: Bytes32) -> bool:
        """Check if a state exists in storage."""
        cursor = self._conn.cursor()
        cursor.execute(
            f"SELECT 1 FROM {STATES.TABLE_NAME} WHERE root = ?",
            (bytes(root),),
        )
        return cursor.fetchone() is not None

    # -------------------------------------------------------------------------
    # Checkpoint Operations
    # -------------------------------------------------------------------------
    #
    # Checkpoints mark finality progress in the consensus protocol.
    # Justified checkpoints have 2/3 validator support.
    # Finalized checkpoints are irreversible - blocks before them never reorg.

    def get_justified_checkpoint(self) -> Checkpoint | None:
        """Retrieve the latest justified checkpoint."""
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
        if row is None:
            return None
        return Checkpoint.decode_bytes(row["data"])

    def put_justified_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Store the latest justified checkpoint."""
        cursor = self._conn.cursor()
        cursor.execute(
            f"""
            INSERT OR REPLACE INTO {CHECKPOINTS.TABLE_NAME} (key, data)
            VALUES (?, ?)
            """,
            (CHECKPOINTS.KEY_JUSTIFIED, checkpoint.encode_bytes()),
        )
        self._conn.commit()

    def get_finalized_checkpoint(self) -> Checkpoint | None:
        """Retrieve the latest finalized checkpoint."""
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
        if row is None:
            return None
        return Checkpoint.decode_bytes(row["data"])

    def put_finalized_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Store the latest finalized checkpoint."""
        cursor = self._conn.cursor()
        cursor.execute(
            f"""
            INSERT OR REPLACE INTO {CHECKPOINTS.TABLE_NAME} (key, data)
            VALUES (?, ?)
            """,
            (CHECKPOINTS.KEY_FINALIZED, checkpoint.encode_bytes()),
        )
        self._conn.commit()

    # -------------------------------------------------------------------------
    # Attestation Operations
    # -------------------------------------------------------------------------
    #
    # Attestations are validator votes on the canonical chain.
    # Fork choice uses the latest attestation from each validator
    # to determine which branch has the most support.

    def get_latest_attestation(self, validator_index: ValidatorIndex) -> AttestationData | None:
        """Retrieve the latest attestation for a validator."""
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
        if row is None:
            return None
        return AttestationData.decode_bytes(row["data"])

    def put_latest_attestation(
        self,
        validator_index: ValidatorIndex,
        attestation: AttestationData,
    ) -> None:
        """Store the latest attestation for a validator."""
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
        self._conn.commit()

    def get_all_latest_attestations(self) -> dict[ValidatorIndex, AttestationData]:
        """Retrieve all latest attestations."""
        cursor = self._conn.cursor()

        # Load all attestations for fork choice computation.
        #
        # This can be a large result set (hundreds of thousands of validators).
        # Consider streaming or batching for production use.
        cursor.execute(f"SELECT validator_index, data FROM {ATTESTATIONS.TABLE_NAME}")
        return {
            ValidatorIndex(row["validator_index"]): AttestationData.decode_bytes(row["data"])
            for row in cursor.fetchall()
        }

    # -------------------------------------------------------------------------
    # Head Tracking
    # -------------------------------------------------------------------------
    #
    # The head is the tip of the canonical chain as determined by fork choice.
    # This is a singleton value that changes as new blocks arrive.

    def get_head_root(self) -> Bytes32 | None:
        """Retrieve the current head block root."""
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
        if row is None:
            return None

        # Head is a raw 32-byte root, not an SSZ-encoded container.
        return Bytes32(row["data"])

    def put_head_root(self, root: Bytes32) -> None:
        """Store the current head block root."""
        cursor = self._conn.cursor()
        cursor.execute(
            f"""
            INSERT OR REPLACE INTO {CHECKPOINTS.TABLE_NAME} (key, data)
            VALUES (?, ?)
            """,
            (CHECKPOINTS.KEY_HEAD, bytes(root)),
        )
        self._conn.commit()

    # -------------------------------------------------------------------------
    # Slot Index Operations
    # -------------------------------------------------------------------------
    #
    # Slots are time intervals (12 seconds each).
    # This index maps slot numbers to blocks, enabling historical queries.
    # Note: not every slot has a block (missed slots happen).

    def get_block_root_by_slot(self, slot: Slot) -> Bytes32 | None:
        """Retrieve block root for a specific slot."""
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
        if row is None:
            return None
        return Bytes32(row["root"])

    def put_block_root_by_slot(self, slot: Slot, root: Bytes32) -> None:
        """Index a block root by its slot."""
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
        self._conn.commit()

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------
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
