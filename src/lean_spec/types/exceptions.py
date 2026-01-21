"""Exception hierarchy for the SSZ type system."""


class SSZError(Exception):
    """Base exception for all SSZ-related errors."""


class SSZTypeError(SSZError):
    """Raised for type-related errors (coercion, definition, invalid types)."""


class SSZValueError(SSZError):
    """Raised for value-related errors (overflow, length, bounds)."""


class SSZSerializationError(SSZError):
    """Raised for serialization errors (encoding, decoding, stream issues).

    Supports optional context for better error diagnostics:

    - type_name: The SSZ type being processed
    - field_name: The field within a container (if applicable)
    - offset: The byte offset where the error occurred
    """

    def __init__(
        self,
        message: str,
        *,
        type_name: str | None = None,
        field_name: str | None = None,
        offset: int | None = None,
    ) -> None:
        """Initialize with message and optional context for better diagnostics."""
        self.type_name = type_name
        self.field_name = field_name
        self.offset = offset

        context_parts = []
        if type_name:
            context_parts.append(f"type={type_name}")
        if field_name:
            context_parts.append(f"field={field_name}")
        if offset is not None:
            context_parts.append(f"offset={offset}")

        context = f" [{', '.join(context_parts)}]" if context_parts else ""
        super().__init__(f"{message}{context}")
