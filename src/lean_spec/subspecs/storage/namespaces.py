"""
Database namespace definitions for storage tables.

Defines table names and schema constants for SQLite storage.
Each namespace represents a logical grouping of related data.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BlockNamespace:
    """
    Namespace for block storage.

    Blocks are stored by their SSZ root hash.
    SSZ-encoded bytes are stored directly.
    """

    TABLE_NAME: str = "blocks"
    """Table name for block storage."""

    CREATE_TABLE: str = """
        CREATE TABLE IF NOT EXISTS blocks (
            root BLOB PRIMARY KEY,
            slot INTEGER NOT NULL,
            data BLOB NOT NULL
        )
    """
    """SQL to create blocks table."""

    CREATE_INDEX: str = """
        CREATE INDEX IF NOT EXISTS idx_blocks_slot ON blocks(slot)
    """
    """SQL to create slot index."""


@dataclass(frozen=True, slots=True)
class StateNamespace:
    """
    Namespace for state storage.

    States are stored by their SSZ root hash.
    SSZ-encoded bytes are stored directly.
    """

    TABLE_NAME: str = "states"
    """Table name for state storage."""

    CREATE_TABLE: str = """
        CREATE TABLE IF NOT EXISTS states (
            root BLOB PRIMARY KEY,
            slot INTEGER NOT NULL,
            data BLOB NOT NULL
        )
    """
    """SQL to create states table."""

    CREATE_INDEX: str = """
        CREATE INDEX IF NOT EXISTS idx_states_slot ON states(slot)
    """
    """SQL to create slot index."""


@dataclass(frozen=True, slots=True)
class CheckpointNamespace:
    """
    Namespace for checkpoint tracking.

    Stores latest justified and finalized checkpoints.
    Uses a key-value pattern with fixed keys.
    """

    TABLE_NAME: str = "checkpoints"
    """Table name for checkpoint storage."""

    KEY_JUSTIFIED: str = "justified"
    """Key for justified checkpoint."""

    KEY_FINALIZED: str = "finalized"
    """Key for finalized checkpoint."""

    KEY_HEAD: str = "head"
    """Key for head block root."""

    CREATE_TABLE: str = """
        CREATE TABLE IF NOT EXISTS checkpoints (
            key TEXT PRIMARY KEY,
            data BLOB NOT NULL
        )
    """
    """SQL to create checkpoints table."""


@dataclass(frozen=True, slots=True)
class AttestationNamespace:
    """
    Namespace for attestation storage.

    Stores latest attestation per validator.
    Indexed by validator index.
    """

    TABLE_NAME: str = "attestations"
    """Table name for attestation storage."""

    CREATE_TABLE: str = """
        CREATE TABLE IF NOT EXISTS attestations (
            validator_index INTEGER PRIMARY KEY,
            data BLOB NOT NULL
        )
    """
    """SQL to create attestations table."""


@dataclass(frozen=True, slots=True)
class SlotIndexNamespace:
    """
    Namespace for slot-to-root mapping.

    Enables lookup of block by slot number.
    Used for historical queries.
    """

    TABLE_NAME: str = "slot_index"
    """Table name for slot index."""

    CREATE_TABLE: str = """
        CREATE TABLE IF NOT EXISTS slot_index (
            slot INTEGER PRIMARY KEY,
            root BLOB NOT NULL
        )
    """
    """SQL to create slot index table."""


# Singleton instances for convenient access
BLOCKS = BlockNamespace()
STATES = StateNamespace()
CHECKPOINTS = CheckpointNamespace()
ATTESTATIONS = AttestationNamespace()
SLOT_INDEX = SlotIndexNamespace()

ALL_NAMESPACES = [BLOCKS, STATES, CHECKPOINTS, ATTESTATIONS, SLOT_INDEX]
"""All namespace definitions for schema initialization."""
