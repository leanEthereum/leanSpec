"""
Storage module for persistent block and state storage.

Provides database abstraction for consensus data persistence.
Uses SQLite for simplicity and correctness.
"""

from lean_spec.node.storage.database import Database
from lean_spec.node.storage.exceptions import (
    StorageCorruptionError,
    StorageReadError,
    StorageWriteError,
)
from lean_spec.node.storage.sqlite import SQLiteDatabase

__all__ = [
    "Database",
    "SQLiteDatabase",
    "StorageCorruptionError",
    "StorageReadError",
    "StorageWriteError",
]
