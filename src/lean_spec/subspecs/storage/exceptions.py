"""
Storage exception hierarchy.

Wraps low-level database and serialization errors with storage-specific context.
This allows callers to handle storage failures uniformly without knowing the
underlying backend (SQLite, etc.).
"""


class StorageError(Exception):
    """Base exception for storage operations."""


class StorageReadError(StorageError):
    """Failed to read from storage."""


class StorageWriteError(StorageError):
    """Failed to write to storage."""


class StorageCorruptionError(StorageError):
    """Stored data failed deserialization."""
