"""
Database namespace definitions for storage tables.

Defines table names and schema constants for SQLite storage.
Each prefix marks a logical grouping of related data.
"""

from __future__ import annotations

from typing import Final

# Blocks: SSZ root primary key, SSZ-encoded bytes stored directly.

BLOCKS_TABLE_NAME: Final = "blocks"
"""Table name for block storage."""

BLOCKS_CREATE_TABLE: Final = """
    CREATE TABLE IF NOT EXISTS blocks (
        root BLOB PRIMARY KEY,
        slot INTEGER NOT NULL,
        data BLOB NOT NULL
    )
"""
"""SQL to create blocks table."""

BLOCKS_CREATE_INDEX: Final = """
    CREATE INDEX IF NOT EXISTS idx_blocks_slot ON blocks(slot)
"""
"""SQL to create slot index."""

# States: SSZ root primary key, SSZ-encoded bytes stored directly.

STATES_TABLE_NAME: Final = "states"
"""Table name for state storage."""

STATES_CREATE_TABLE: Final = """
    CREATE TABLE IF NOT EXISTS states (
        root BLOB PRIMARY KEY,
        slot INTEGER NOT NULL,
        data BLOB NOT NULL
    )
"""
"""SQL to create states table."""

STATES_CREATE_INDEX: Final = """
    CREATE INDEX IF NOT EXISTS idx_states_slot ON states(slot)
"""
"""SQL to create slot index."""

# Checkpoints: key-value table with fixed keys for justified/finalized/head/genesis-time.

CHECKPOINTS_TABLE_NAME: Final = "checkpoints"
"""Table name for checkpoint storage."""

CHECKPOINTS_KEY_JUSTIFIED: Final = "justified"
"""Key for justified checkpoint."""

CHECKPOINTS_KEY_FINALIZED: Final = "finalized"
"""Key for finalized checkpoint."""

CHECKPOINTS_KEY_HEAD: Final = "head"
"""Key for head block root."""

CHECKPOINTS_KEY_GENESIS_TIME: Final = "genesis_time"
"""Key for genesis time. Enables self-contained restarts without external config."""

CHECKPOINTS_CREATE_TABLE: Final = """
    CREATE TABLE IF NOT EXISTS checkpoints (
        key TEXT PRIMARY KEY,
        data BLOB NOT NULL
    )
"""
"""SQL to create checkpoints table."""

# Slot index: slot-to-root mapping for historical queries.

SLOT_INDEX_TABLE_NAME: Final = "slot_index"
"""Table name for slot index."""

SLOT_INDEX_CREATE_TABLE: Final = """
    CREATE TABLE IF NOT EXISTS slot_index (
        slot INTEGER PRIMARY KEY,
        root BLOB NOT NULL
    )
"""
"""SQL to create slot index table."""

# State root index: state-root-to-block-root mapping for checkpoint sync and API.

STATE_ROOT_INDEX_TABLE_NAME: Final = "state_root_index"
"""Table name for state root index."""

STATE_ROOT_INDEX_CREATE_TABLE: Final = """
    CREATE TABLE IF NOT EXISTS state_root_index (
        state_root BLOB PRIMARY KEY,
        block_root BLOB NOT NULL
    )
"""
"""SQL to create state root index table."""
