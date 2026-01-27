"""
Storage module for persistent block and state storage.

Provides database abstraction for consensus data persistence.
Uses SQLite for simplicity and correctness.
"""

from .database import Database
from .namespaces import BlockNamespace, CheckpointNamespace, StateNamespace
from .sqlite import SQLiteDatabase

__all__ = [
    "Database",
    "SQLiteDatabase",
    "BlockNamespace",
    "StateNamespace",
    "CheckpointNamespace",
]
