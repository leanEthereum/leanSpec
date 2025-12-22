"""Exception hierarchy for the SSZ type system."""


class SSZError(Exception):
    """Base exception for all SSZ-related errors."""


class SSZTypeError(SSZError):
    """Raised for type-related errors (coercion, definition, invalid types)."""


class SSZValueError(SSZError):
    """Raised for value-related errors (overflow, length, bounds)."""


class SSZSerializationError(SSZError):
    """Raised for serialization errors (encoding, decoding, stream issues)."""
