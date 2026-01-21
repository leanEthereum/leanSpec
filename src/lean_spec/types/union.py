"""SSZ Union type."""

from __future__ import annotations

import io
from typing import (
    IO,
    Any,
    ClassVar,
    Final,
    Tuple,
    Type,
    cast,
)

from pydantic import model_validator
from typing_extensions import Self

from .exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from .ssz_base import SSZModel, SSZType

# Constants for Union implementation
MAX_UNION_OPTIONS: Final[int] = 128
"""Maximum number of options allowed in a Union (uint8 selector range)."""

SELECTOR_BYTE_SIZE: Final[int] = 1
"""Size in bytes of the selector field in SSZ encoding."""


class SSZUnion(SSZModel):
    """Base class for SSZ Union types.

    Represents tagged sum types (discriminated unions) holding exactly one value
    from a predefined set of SSZ types.

    Subclasses must define OPTIONS as a tuple of SSZ types (or None at index 0).

    Type safety:

    - Selector must be valid index into OPTIONS tuple
    - Values are validated and coerced to selected type
    - None only allowed at index 0

    SSZ encoding: selector byte followed by serialized value.
    """

    OPTIONS: ClassVar[Tuple[Type[SSZType] | None, ...]]
    """Tuple of possible types for this Union.

    Each position corresponds to a selector index.
    Only index 0 may be None.
    All non-None options must implement the SSZType protocol.

    Example:
        OPTIONS = (None, Uint16, Uint32) allows:
        - selector=0 -> None (null variant)
        - selector=1 -> Uint16 values
        - selector=2 -> Uint32 values
    """

    selector: int
    """The 0-based index of the currently selected option."""

    value: Any
    """The value currently stored in this Union."""

    @model_validator(mode="before")
    @classmethod
    def _validate_union_data(cls, data: Any) -> dict[str, Any]:
        """Validate selector and value together."""
        # Check required class attributes and get options
        if not hasattr(cls, "OPTIONS") or not isinstance(cls.OPTIONS, tuple):
            raise SSZTypeError(f"{cls.__name__} must define OPTIONS as a tuple of SSZ types")

        options, options_count = cls.OPTIONS, len(cls.OPTIONS)

        # Validate OPTIONS constraints
        if options_count == 0:
            raise SSZTypeError(f"{cls.__name__}: OPTIONS cannot be empty")
        if options_count > MAX_UNION_OPTIONS:
            raise SSZTypeError(
                f"{cls.__name__}: has {options_count} options, max is {MAX_UNION_OPTIONS}"
            )
        if options[0] is None and options_count == 1:
            raise SSZTypeError(f"{cls.__name__}: cannot have None as the only option")

        # Validate None placement (only at index 0) and types
        for i, opt in enumerate(options):
            if opt is None and i != 0:
                raise SSZTypeError(f"{cls.__name__}: None only allowed at index 0, found at {i}")
            elif opt is not None and not isinstance(opt, type):
                raise SSZTypeError(f"{cls.__name__}: option {i} must be a type, got {type(opt)}")

        # Extract selector and value from input
        selector = data.get("selector")
        value = data.get("value")

        # Validate selector
        if not isinstance(selector, int) or not 0 <= selector < options_count:
            sel = selector if isinstance(selector, int) else -1
            raise SSZValueError(f"{cls.__name__}: selector {sel} out of range [0, {options_count})")

        # Handle None option
        if (selected_type := options[selector]) is None:
            if value is not None:
                raise SSZTypeError(f"Expected None, got {type(value).__name__}")
            return {"selector": selector, "value": None}

        # Handle non-None option - coerce value if needed
        if isinstance(value, selected_type):
            return {"selector": selector, "value": value}

        try:
            coerced_value = cast(Any, selected_type)(value)
            return {"selector": selector, "value": coerced_value}
        except Exception as e:
            raise SSZTypeError(
                f"Expected {selected_type.__name__}, got {type(value).__name__}"
            ) from e

    @property
    def selected_type(self) -> Type[SSZType] | None:
        """The type class of the currently selected option."""
        return self.OPTIONS[self.selector]

    @classmethod
    def options(cls) -> Tuple[Type[SSZType] | None, ...]:
        """Get the tuple of possible types for this Union."""
        return cls.OPTIONS

    @classmethod
    def is_fixed_size(cls) -> bool:
        """Union types are always variable-size in SSZ."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """Union types are variable-size and don't have fixed length."""
        raise SSZTypeError(f"{cls.__name__}: variable-size union has no fixed byte length")

    def serialize(self, stream: IO[bytes]) -> int:
        """Serialize this Union to a byte stream in SSZ format."""
        # Write selector byte and return early for None
        stream.write(self.selector.to_bytes(SELECTOR_BYTE_SIZE, byteorder="little"))
        return SELECTOR_BYTE_SIZE + (
            cast(SSZType, self.value).serialize(stream) if self.selected_type is not None else 0
        )

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Deserialize a Union from a byte stream using SSZ format."""
        # Validate scope for selector byte
        if scope < SELECTOR_BYTE_SIZE:
            raise SSZSerializationError(f"{cls.__name__}: scope too small for selector")

        # Read selector byte
        selector_bytes = stream.read(SELECTOR_BYTE_SIZE)
        if len(selector_bytes) != SELECTOR_BYTE_SIZE:
            raise SSZSerializationError(
                f"{cls.__name__}: "
                f"expected {SELECTOR_BYTE_SIZE} selector bytes, got {len(selector_bytes)}"
            )

        selector = int.from_bytes(selector_bytes, byteorder="little")
        remaining_bytes = scope - SELECTOR_BYTE_SIZE

        # Validate selector range
        if not 0 <= selector < len(cls.OPTIONS):
            raise SSZValueError(
                f"{cls.__name__}: selector {selector} out of range [0, {len(cls.OPTIONS)})"
            )

        selected_type = cls.OPTIONS[selector]

        # Handle None option
        if selected_type is None:
            if remaining_bytes != 0:
                raise SSZSerializationError(f"{cls.__name__}: None arm must have no payload bytes")
            return cls(selector=selector, value=None)

        # Handle non-None option
        if selected_type.is_fixed_size() and hasattr(selected_type, "get_byte_length"):
            required_bytes = selected_type.get_byte_length()
            if remaining_bytes < required_bytes:
                raise SSZSerializationError(
                    f"{cls.__name__}: expected {required_bytes} bytes, got {remaining_bytes}"
                )

        # Deserialize value
        try:
            value = selected_type.deserialize(stream, remaining_bytes)
            return cls(selector=selector, value=value)
        except Exception as e:
            raise SSZSerializationError(
                f"{cls.__name__}: failed to deserialize {selected_type.__name__}: {e}"
            ) from e

    def encode_bytes(self) -> bytes:
        """Encode this Union to bytes."""
        with io.BytesIO() as stream:
            self.serialize(stream)
            return stream.getvalue()

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Decode a Union from bytes."""
        return cls.deserialize(io.BytesIO(data), len(data))

    def __repr__(self) -> str:
        """Return a readable string representation of this Union."""
        return f"{type(self).__name__}(selector={self.selector}, value={self.value!r})"
