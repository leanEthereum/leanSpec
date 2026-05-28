"""
Storage module for persistent block and state storage.

Provides database abstraction for consensus data persistence.
Uses SQLite for simplicity and correctness.
"""

from .database import Database
from .exceptions import StorageCorruptionError, StorageReadError, StorageWriteError
from .sqlite import SQLiteDatabase

__all__ = [
    "Database",
    "SQLiteDatabase",
    "StorageCorruptionError",
    "StorageReadError",
    "StorageWriteError",
]
