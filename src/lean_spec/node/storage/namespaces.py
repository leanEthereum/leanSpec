"""Table names and schema SQL for the SQLite storage backend."""

from __future__ import annotations

from typing import Final

# Blocks: SSZ root primary key, SSZ-encoded bytes stored directly.

BLOCKS_TABLE_NAME: Final = "blocks"

BLOCKS_CREATE_TABLE: Final = """
    CREATE TABLE IF NOT EXISTS blocks (
        root BLOB PRIMARY KEY,
        slot INTEGER NOT NULL,
        data BLOB NOT NULL
    )
"""

BLOCKS_CREATE_INDEX: Final = """
    CREATE INDEX IF NOT EXISTS idx_blocks_slot ON blocks(slot)
"""

# States: SSZ root primary key, SSZ-encoded bytes stored directly.

STATES_TABLE_NAME: Final = "states"

STATES_CREATE_TABLE: Final = """
    CREATE TABLE IF NOT EXISTS states (
        root BLOB PRIMARY KEY,
        slot INTEGER NOT NULL,
        data BLOB NOT NULL
    )
"""

STATES_CREATE_INDEX: Final = """
    CREATE INDEX IF NOT EXISTS idx_states_slot ON states(slot)
"""

# Checkpoints: key-value table with fixed keys for justified/finalized/head/genesis-time.

CHECKPOINTS_TABLE_NAME: Final = "checkpoints"

CHECKPOINTS_KEY_JUSTIFIED: Final = "justified"

CHECKPOINTS_KEY_FINALIZED: Final = "finalized"

CHECKPOINTS_KEY_HEAD: Final = "head"

CHECKPOINTS_KEY_GENESIS_TIME: Final = "genesis_time"
"""Persisted so the node can restart without external genesis config."""

CHECKPOINTS_CREATE_TABLE: Final = """
    CREATE TABLE IF NOT EXISTS checkpoints (
        key TEXT PRIMARY KEY,
        data BLOB NOT NULL
    )
"""

# Slot index: slot-to-root mapping for historical queries.

SLOT_INDEX_TABLE_NAME: Final = "slot_index"

SLOT_INDEX_CREATE_TABLE: Final = """
    CREATE TABLE IF NOT EXISTS slot_index (
        slot INTEGER PRIMARY KEY,
        root BLOB NOT NULL
    )
"""

# State root index: state-root-to-block-root mapping for checkpoint sync and API.

STATE_ROOT_INDEX_TABLE_NAME: Final = "state_root_index"

STATE_ROOT_INDEX_CREATE_TABLE: Final = """
    CREATE TABLE IF NOT EXISTS state_root_index (
        state_root BLOB PRIMARY KEY,
        block_root BLOB NOT NULL
    )
"""
