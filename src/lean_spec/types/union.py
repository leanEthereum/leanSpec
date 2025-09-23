"""
SSZ Union Type - Tagged sum type with selector byte + optional value.

Encoding: [selector: uint8][value: SSZ(selected_type)]
- Selector: 1 byte indicating which option is selected (0-based)
- Value: SSZ-encoded value (omitted for None option at index 0)
- Max 128 options, only index 0 may be None
- Always variable-size for SSZ purposes

Usage: Union[None, Uint16, Uint32] creates specialized type
"""

from __future__ import annotations

import io
from typing import (
    IO,
    Any,
    ClassVar,
    Dict,
    Tuple,
    Type,
    cast,
)

from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema
from typing_extensions import Self

from .ssz_base import SSZType

_UNION_CACHE: Dict[
    Tuple[Type["Union"], Tuple[Type[SSZType] | None, ...]],
    Type["Union"],
] = {}
"""
Global cache for specialized Union types to avoid recreating the same types

Key: (base Union class, tuple of option types)
Value: The specialized Union class
"""


class Union(SSZType):
    """
    SSZ Union type holding one value from a predefined set of types.

    Create specialized types: Union[None, Uint16, Uint32]
    Create instances: MyUnion(selector=1, value=Uint16(42))
    Access data: instance.selector, instance.selected_type, instance.value

    Constraints:
    - Max 128 options, only index 0 may be None
    - All non-None options must implement SSZType protocol
    - Values auto-coerced to selected type when possible

    Attributes:
        OPTIONS: Tuple of possible types for this specialized Union.
    """

    # Class variable holding the possible types for this specialized Union
    # This gets set automatically when you create a Union type like Union[A, B, C]
    OPTIONS: ClassVar[Tuple[Type[SSZType] | None, ...]]

    def __class_getitem__(
        cls, options: Tuple[Type[SSZType] | None, ...] | Type[SSZType] | None
    ) -> Type["Union"]:
        """
        Create specialized Union type with given options.

        Called when using Union[A, B, C] syntax. Creates and caches new
        specialized Union class.

        Args:
            options: Single type or tuple of types. Only index 0 may be None.

        Returns:
            Specialized Union class for the given option types.

        Raises:
            TypeError: Invalid options (wrong count, None not at index 0,
                      non-types, or missing SSZType protocol methods).
        """
        # Normalize input - Python passes single types as non-tuples
        #
        # Convert Union[Uint16] -> Union[(Uint16,)] for consistent processing
        if not isinstance(options, tuple):
            options = (options,)

        # Validate option count constraints
        #
        # Must have at least one option to be meaningful
        if len(options) < 1:
            raise TypeError("Union expects at least one option")
        # SSZ selector is uint8, so max 256 options, but we limit to 128 for safety
        if len(options) > 128:
            raise TypeError(f"Union expects at most 128 options, got {len(options)}")

        # Validate each option type and enforce None-only-at-index-0 rule
        norm_opts: list[Type[SSZType] | None] = list(options)
        for i, opt in enumerate(norm_opts):
            # Handle None option - only allowed at index 0 (the "null" variant)
            if opt is None:
                if i != 0:
                    raise TypeError("Only option 0 may be None")
                continue  # Skip further validation for None

            # Ensure option is actually a type/class, not an instance
            if not isinstance(opt, type):
                raise TypeError(f"Option {i} must be a type")

            # Check that the type implements the SSZType protocol
            #
            # We use duck typing - check for required methods rather than inheritance
            required = ("serialize", "deserialize", "encode_bytes", "decode_bytes", "is_fixed_size")
            if missing := [m for m in required if not hasattr(opt, m)]:
                raise TypeError(
                    f"Option at index {i} must be an SSZType-like type implementing: "
                    f"{', '.join(missing)}"
                )

        # Additional validation - None-only unions are not useful
        #
        # If first option is None, require at least one non-None option
        if norm_opts[0] is None and len(norm_opts) < 2:
            raise TypeError("Union with None at option 0 must have at least one non-None option")

        # Check cache to avoid recreating identical Union types
        #
        # Key combines the base class and the exact tuple of option types
        key = (cls, tuple(norm_opts))
        if key in _UNION_CACHE:
            return _UNION_CACHE[key]  # Return existing specialized type

        # Create new specialized Union class dynamically
        #
        # Generate a readable name showing the options: "Union[Uint16, Uint32]"
        label = ", ".join(getattr(opt, "__name__", "None") for opt in norm_opts)

        # Create new class inheriting from the base Union class
        # The OPTIONS attribute holds the tuple of possible types
        new_type = type(
            f"{cls.__name__}[{label}]",  # Class name for debugging
            (cls,),  # Base classes
            {"OPTIONS": tuple(norm_opts)},  # Class attributes
        )

        # Cache the new type and return it
        _UNION_CACHE[key] = new_type
        return new_type

    def __init__(self, *, selector: int, value: Any) -> None:
        """
        Create Union instance with explicit selector and value.

        Args:
            selector: 0-based index of selected option (0 to len(OPTIONS)-1).
            value: Value for selected option (None if selector=0 and OPTIONS[0] is None).
                  Values are auto-coerced to target type when possible.

        Raises:
            ValueError: Invalid selector (not int or out of range).
            TypeError: Value/selector mismatch (None value for non-None option, etc).
        """
        # Validate the selector is a valid index
        #
        # Must be an integer and within the bounds of the OPTIONS tuple
        if not isinstance(selector, int) or not 0 <= selector < len(self.OPTIONS):
            raise ValueError(f"Invalid selector {selector} for {len(self.OPTIONS)} options")

        # Handle the special None option case
        opt_t = self.OPTIONS[selector]  # Get the type for the selected option
        if opt_t is None:
            # If None option is selected, value must also be None
            if value is not None:
                raise TypeError("Selected option is None, therefore value must be None")
            # Store the None selector and value directly
            self._selector = selector
            self._value = None
            return

        # Handle non-None options - coerce value to the target type
        self._selector = selector
        # If value is already the correct type, use it as-is
        # Otherwise, try to coerce it by calling the type constructor
        # This allows Union(selector=1, value=42) to work for Uint16 options
        self._value = value if isinstance(value, opt_t) else cast(Any, opt_t)(value)

    @classmethod
    def options(cls) -> Tuple[Type[SSZType] | None, ...]:
        """
        Get tuple of possible types for this Union.

        Returns:
            Tuple of types where position corresponds to selector index.
        """
        return cls.OPTIONS

    @property
    def selector(self) -> int:
        """
        The 0-based index of the currently selected option.

        Returns:
            Selector index (0 to len(OPTIONS)-1).
        """
        return self._selector

    @property
    def selected_type(self) -> Type[SSZType] | None:
        """
        The type of the currently selected option.

        Returns:
            Type class of selected option, or None for null option.
        """
        return self.OPTIONS[self.selector]

    @property
    def value(self) -> Any:
        """
        The value currently stored in this Union.

        Returns:
            Stored value (None for null option, SSZType instance otherwise).
        """
        return self._value

    @classmethod
    def is_fixed_size(cls) -> bool:
        """
        Indicate whether this Union type has a fixed size.

        Union types are always considered variable-size in SSZ because
        the total serialized length depends on which option is selected,
        even if some individual options are fixed-size.

        Returns:
            Always False - unions are variable-size by definition.
        """
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """
        Get the byte length of the Union type.

        Since Union types are variable-size, this method always raises TypeError.

        Raises:
            TypeError: Union types are variable-size and don't have a fixed byte length.
        """
        raise TypeError("Union types are variable-size and don't have a fixed byte length")

    def serialize(self, stream: IO[bytes]) -> int:
        """
        Serialize this Union to a byte stream.

        Writes the Union in SSZ format: one selector byte followed by
        the SSZ serialization of the value (if not None option).

        Args:
            stream: A writable byte stream to write the serialized data to.

        Returns:
            The total number of bytes written to the stream.
        """
        # Write the selector byte (which option is selected)
        stream.write(self.selector.to_bytes(length=1, byteorder="little"))

        # If None option is selected, we're done (no value to write)
        if self.selected_type is None:
            return 1

        # Write the value using its SSZ serialization and add to byte count
        return 1 + cast(SSZType, self.value).serialize(stream)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        r"""
        Deserialize a Union from a byte stream.

        Reads the selector byte, then deserializes the value based on
        the selected option type.

        Args:
            stream: A readable byte stream containing the serialized Union data.
            scope: The maximum number of bytes that can be read from the stream
                  for this Union (used for bounds checking).

        Returns:
            A new Union instance with the deserialized data.

        Raises:
            ValueError: If scope is too small, selector is invalid, or None
                       option has unexpected payload bytes.
            IOError: If stream ends prematurely or selected option needs more
                    bytes than available.

        """
        # Validate we have enough bytes for at least the selector
        #
        # Every Union needs at least 1 byte for the selector
        if scope < 1:
            raise ValueError("Scope too small for Union selector")

        # Read the selector byte from the stream
        sel_bytes = stream.read(1)
        # Ensure we actually got the byte (stream might be truncated)
        if len(sel_bytes) != 1:
            raise IOError("Stream ended reading Union selector")

        # Convert selector byte to integer and validate it
        #
        # Union selector is stored as little-endian uint8
        selector = int.from_bytes(sel_bytes, "little")
        # Selector must be a valid index into our OPTIONS tuple
        if not 0 <= selector < len(cls.OPTIONS):
            raise ValueError(f"Selector {selector} out of range for {len(cls.OPTIONS)} options")

        # Determine the selected option type and remaining bytes
        #
        # Get the type for this selector
        opt_t = cls.OPTIONS[selector]
        # Bytes left after reading selector
        remaining = scope - 1

        # Handle None option (no value payload expected)
        if opt_t is None:
            # None option should have no additional bytes
            if remaining != 0:
                raise ValueError("Invalid encoding: None arm must have no payload bytes")
            return cls(selector=selector, value=None)

        # Validate fixed-size constraints for non-None options
        #
        # If the selected type is fixed-size, ensure we have enough bytes
        if opt_t.is_fixed_size() and hasattr(opt_t, "get_byte_length"):
            # How many bytes this type needs
            need = opt_t.get_byte_length()
            if remaining < need:
                raise IOError(f"Need {need} bytes, got {remaining}")

        # Deserialize the value using the selected type's deserializer
        #
        # Let the selected type handle parsing its own format from the remaining bytes
        return cls(selector=selector, value=opt_t.deserialize(stream, remaining))

    def encode_bytes(self) -> bytes:
        r"""
        Encode this Union to a bytes object.

        Convenience method that serializes the Union to an in-memory buffer
        and returns the resulting bytes.

        Returns:
            The SSZ-encoded bytes representation of this Union.
        """
        with io.BytesIO() as s:
            self.serialize(s)
            return s.getvalue()

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        r"""
        Decode a Union from a bytes object.

        Convenience method that deserializes a Union from raw bytes.

        Args:
            data: The SSZ-encoded bytes to decode.

        Returns:
            A new Union instance decoded from the bytes.

        Raises:
            ValueError: If the data is invalid or corrupted.
            IOError: If the data is truncated.
        """
        with io.BytesIO(data) as s:
            return cls.deserialize(s, len(data))

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """
        Generate Pydantic core schema for Union validation and serialization.

        This method enables Pydantic integration, allowing Unions to be used
        in Pydantic models with automatic validation and serialization.

        The schema accepts:
        1. Existing Union instances (pass-through)
        2. Dictionaries with 'selector' and 'value' keys

        And serializes Unions to dictionaries with 'selector' and 'value' keys.

        Args:
            source_type: The source type being processed (usually this Union class).
            handler: Pydantic's schema generation handler.

        Returns:
            A Pydantic CoreSchema that can validate and serialize Union instances.
        """

        def from_mapping(v: Any) -> "Union":
            """Convert input to Union instance for Pydantic validation."""
            # If already a Union instance, pass it through unchanged
            if isinstance(v, cls):
                return v

            # Must be a dict with both required keys
            if not isinstance(v, dict) or not {"selector", "value"} <= v.keys():
                raise ValueError(f"Expected {cls.__name__} or dict with 'selector', 'value'")

            # Validate selector is valid integer index
            sel = v["selector"]
            if not isinstance(sel, int) or not 0 <= sel < len(cls.OPTIONS):
                raise ValueError(f"Invalid selector {sel}")

            # Handle None option separately
            opt_t = cls.OPTIONS[sel]
            if opt_t is None:
                if v["value"] is not None:
                    raise ValueError("None option requires None value")
                return cls(selector=sel, value=None)

            # For non-None options, coerce the value to the target type
            return cls(selector=sel, value=cast(Any, opt_t)(v["value"]))

        def to_obj(u: "Union") -> dict[str, Any]:
            """Convert Union instance to dict for Pydantic serialization."""
            return {
                "selector": u.selector,  # Always include the selector
                # Include the actual value for serialization
                "value": None if u.selected_type is None else cast(SSZType, u.value),
            }

        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                core_schema.no_info_plain_validator_function(from_mapping),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(to_obj),
        )

    def __eq__(self, other: object) -> bool:
        """
        Check structural equality between Union instances.

        Two Unions are equal if they are the same specialized type,
        have the same selector, and their values are equal.

        Args:
            other: The object to compare with.

        Returns:
            True if the Unions are structurally equal, False otherwise.
        """
        return (
            isinstance(other, type(self))
            and self.selector == other.selector
            and self.value == other.value
        )

    def __hash__(self) -> int:
        """
        Compute hash value for use in sets and dictionaries.

        The hash is based on the Union's type, selector, and value,
        ensuring that equal Unions have equal hashes.

        Returns:
            An integer hash value.
        """
        return hash((type(self), self.selector, self.value))

    def __repr__(self) -> str:
        """
        Return a readable string representation of this Union.

        The representation shows the Union type name, selector, and value,
        making it easy to understand the Union's state during debugging.

        Returns:
            A string representation in the format:
            "UnionTypeName(selector=N, value=repr(value))"
        """
        return f"{type(self).__name__}(selector={self.selector}, value={self.value!r})"
