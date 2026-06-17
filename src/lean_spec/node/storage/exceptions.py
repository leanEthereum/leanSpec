"""Storage exceptions that wrap backend and serialization failures."""


class StorageError(Exception):
    """Base exception for storage operations."""


class StorageReadError(StorageError):
    """Failed to read from storage."""


class StorageWriteError(StorageError):
    """Failed to write to storage."""


class StorageCorruptionError(StorageError):
    """Stored data failed deserialization."""
