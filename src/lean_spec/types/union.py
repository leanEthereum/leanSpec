"""
Union Type Specification.

A strict SSZ Union type: a tagged sum type encoded as:

    selector: uint8  (1 byte)
    value:    SSZ(value_type)  (0 or more bytes depending on selected option)

Notes:
- Only option index 0 may be None (the "null" option). If selected, the value
  is omitted and the encoding is just the selector byte.
- A Union is always variable-size overall because its total length depends on
  which option is selected (even if some options are fixed-size individually).
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
Cache for dynamically created specialized Union types:
key = (base-class, options-tuple-identity)
"""


class Union(SSZType):
    """
    A strict SSZ Union type.

    Create specialized types with `Union[Opt0, Opt1, ..., OptN]`, where each
    OptK is an SSZ type, and only Opt0 may be None (the "null" option).

    Example:
        MyUnion = Union[None, Uint16, List[Uint8, 32]]
        x = MyUnion(selector=1, value=Uint16(42))
        y = MyUnion(selector=0, value=None)   # the "None" arm

    Instances are constructed with explicit selector + value for clarity and
    strictness.
    """

    OPTIONS: ClassVar[Tuple[Type[SSZType] | None, ...]]
    """The list of options for this specialized Union type."""

    def __class_getitem__(
        cls, options: Tuple[Type[SSZType] | None, ...] | Type[SSZType] | None
    ) -> Type["Union"]:
        """
        Create a specific Union type with the given options.

        Usage:
            Union[None, Uint16, Vector[Uint8, 3]]
            Union[Uint32]  # single option, no None arm
        """
        # Normalize single-element syntax (Python passes a non-tuple in that case).
        if not isinstance(options, tuple):
            options = (options,)

        # Basic arity checks.
        if len(options) < 1:
            raise TypeError("Union expects at least one option")
        if len(options) > 128:
            raise TypeError(f"Union expects at most 128 options, got {len(options)}")

        # Validate option types: only index 0 may be None.
        # Use duck-typing for SSZ types (List/Vector specializations may not
        # literally subclass SSZType but implement the protocol).
        norm_opts: list[Type[SSZType] | None] = list(options)
        for i, opt in enumerate(norm_opts):
            if opt is None:
                if i != 0:
                    raise TypeError("Only option 0 may be None")
                continue
            if not isinstance(opt, type):
                raise TypeError(f"Option at index {i} must be a type (or None at index 0)")
            # Minimal SSZType protocol used at runtime
            required_methods = (
                "serialize",
                "deserialize",
                "encode_bytes",
                "decode_bytes",
                "is_fixed_size",
            )
            missing = [m for m in required_methods if not hasattr(opt, m)]
            if missing:
                raise TypeError(
                    "Option at index "
                    f"{i} must be an SSZType-like type implementing: "
                    f"{', '.join(required_methods)}"
                )

        # If there is a None option, require at least one additional option.
        if norm_opts[0] is None and len(norm_opts) < 2:
            raise TypeError("Union with None at option 0 must have at least one non-None option")

        key = (cls, tuple(norm_opts))
        if key in _UNION_CACHE:
            return _UNION_CACHE[key]

        # Build the specialized class.
        label = ", ".join(opt.__name__ if opt is not None else "None" for opt in norm_opts)
        type_name = f"{cls.__name__}[{label}]"
        new_type = type(
            type_name,
            (cls,),
            {
                "OPTIONS": tuple(norm_opts),
                "__doc__": (
                    "A Union over options: "
                    f"{label}.\n\n"
                    "Select with selector=index and provide value matching the "
                    "selected option.\n"
                    "If selector==0 and option 0 is None, value must be None."
                ),
            },
        )
        _UNION_CACHE[key] = new_type
        return new_type

    def __init__(self, *, selector: int, value: Any) -> None:
        """
        Construct a Union value by explicitly specifying the selected arm.

        Args:
            selector: The index of the selected option (0-based).
            value:    The value for that option, or None if option 0 is the
                      None arm.

        Raises:
            TypeError / ValueError for invalid selector or mismatched value type.
        """
        # Validate selector in range.
        if not isinstance(selector, int) or selector < 0 or selector >= len(self.OPTIONS):
            raise ValueError(
                "Invalid selector "
                f"{selector} for {type(self).__name__} "
                f"with {len(self.OPTIONS)} options"
            )

        # Enforce the typing rule for the chosen arm.
        opt_t = self.OPTIONS[selector]
        if opt_t is None:
            if value is not None:
                raise TypeError("Selected option is None, therefore value must be None")
            self._selector = selector
            self._value = None
            return

        # Coerce the provided value into the selected SSZ type if needed.
        if isinstance(value, opt_t):
            coerced = value
        else:
            coerced = cast(Any, opt_t)(value)
        self._selector = selector
        self._value = coerced

    @classmethod
    def options(cls) -> Tuple[Type[SSZType] | None, ...]:
        """Return the options for this specialized Union type."""
        return cls.OPTIONS

    def selector(self) -> int:
        """Return the selected option index."""
        return self._selector

    def selected_type(self) -> Type[SSZType] | None:
        """Return the SSZ type of the selected option (or None for the null arm)."""
        return self.OPTIONS[self.selector()]

    def value(self) -> Any:
        """Return the current value (or None if the null arm is selected)."""
        return self._value

    @classmethod
    def is_fixed_size(cls) -> bool:
        """
        A Union is considered variable-size overall.

        Even if some (or all) arms are individually fixed-size, the total length
        depends on which arm is selected.
        """
        return False

    def serialize(self, stream: IO[bytes]) -> int:
        """
        Serialize as: 1 byte selector, followed by the selected arm's SSZ
        encoding (if any).

        Returns:
            Total number of bytes written.
        """
        # Write selector.
        sel = self.selector()
        stream.write(sel.to_bytes(length=1, byteorder="little"))
        total = 1

        # Write value if not None-arm.
        opt_t = self.selected_type()
        if opt_t is None:
            return total

        val = cast(SSZType, self.value())
        total += val.serialize(stream)
        return total

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Deserialize from a stream with the provided scope (total bytes available).

        Layout:
            [ selector:1 ][ value-bytes: (scope-1) ]

        For the None arm (option 0 == None), scope must be exactly 1.
        For any other arm, the remaining scope-1 bytes are passed to that arm's
        .deserialize(stream, remaining_scope).
        """
        if scope < 1:
            raise ValueError("Scope too small: cannot read Union selector")

        # Read selector byte.
        sel_bytes = stream.read(1)
        if len(sel_bytes) != 1:
            raise IOError("Stream ended prematurely while decoding Union selector")

        selector = int.from_bytes(sel_bytes, "little")
        if selector < 0 or selector >= len(cls.OPTIONS):
            raise ValueError(
                "Selected index "
                f"{selector} is out of range for {cls.__name__} "
                f"with {len(cls.OPTIONS)} options"
            )

        remaining = scope - 1
        opt_t = cls.OPTIONS[selector]

        if opt_t is None:
            # None-arm: must have no payload.
            if remaining != 0:
                raise ValueError("Invalid encoding: None arm must have no payload bytes")
            return cls(selector=selector, value=None)

        # If the selected arm is fixed-size, ensure we have enough bytes.
        if opt_t.is_fixed_size():
            # Most fixed-size SSZ types expose get_byte_length()
            expected = getattr(opt_t, "get_byte_length", None)
            if callable(expected):
                need = expected()
                if remaining < need:
                    raise IOError(
                        f"Insufficient scope for {opt_t.__name__}: need {need}, got {remaining}"
                    )

        # Non-None arm: delegate to the selected type with the remaining scope.
        val = opt_t.deserialize(stream, remaining)
        return cls(selector=selector, value=val)

    def encode_bytes(self) -> bytes:
        """Serialize to bytes [selector || value-encoding]."""
        with io.BytesIO() as s:
            self.serialize(s)
            return s.getvalue()

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Parse from bytes [selector || value-encoding]."""
        with io.BytesIO(data) as s:
            return cls.deserialize(s, len(data))

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """
        Pydantic validation:
        - Accept an instance of this specialized Union (pass-through).
        - Or accept a dict like {'selector': int, 'value': <obj>} and build an
          instance. The 'value' is validated/constructed using the selected
          option's schema.
        - Serialize to a dict {'selector': int, 'value': <obj>} (value None for
          the None arm).
        """

        def from_mapping(v: Any) -> "Union":
            if isinstance(v, cls):
                return v
            if not isinstance(v, dict):
                # Use ValueError so Pydantic wraps into ValidationError
                raise ValueError(f"Expected {cls.__name__} or dict, got {type(v).__name__}")
            if "selector" not in v or "value" not in v:
                raise ValueError("Expected dict with 'selector' and 'value' keys")
            sel = v["selector"]
            if not isinstance(sel, int):
                raise ValueError("selector must be int")
            if sel < 0 or sel >= len(cls.OPTIONS):
                raise ValueError(f"selector {sel} out of range for {cls.__name__}")

            opt_t = cls.OPTIONS[sel]
            if opt_t is None:
                if v["value"] is not None:
                    # ValueError -> Pydantic ValidationError
                    raise ValueError("value must be None for None arm (selector 0)")
                return cls(selector=sel, value=None)

            # Construct the inner value using the selected SSZ type.
            parsed = cast(Any, opt_t)(v["value"])
            return cls(selector=sel, value=parsed)

        # Serializer to a simple mapping.
        def to_obj(u: "Union") -> dict[str, Any]:
            sel = u.selector()
            val_t = u.selected_type()
            if val_t is None:
                return {"selector": sel, "value": None}
            val = cast(SSZType, u.value())
            return {"selector": sel, "value": val}

        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                core_schema.no_info_plain_validator_function(from_mapping),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(to_obj),
        )

    def __eq__(self, other: object) -> bool:
        """
        Structural equality for Union instances.

        Two Unions are equal if:
            - they are of the exact same specialized Union type, and
            - they have the same selector, and
            - their contained values are equal.

        Args:
            other: The object to compare against.

        Returns:
            True if both are equivalent Unions, False otherwise.
        """
        if not isinstance(other, type(self)):
            return False
        return (self.selector() == other.selector()) and (self.value() == other.value())

    def __hash__(self) -> int:
        """
        Hash based on the specialized Union type, selector, and value.

        Ensures Unions can be used reliably as dictionary keys or in sets.
        Two Unions that compare equal will also have the same hash.
        """
        return hash((type(self), self.selector(), self.value()))

    def __repr__(self) -> str:
        """Return a readable representation showing the selector and value."""
        tname = type(self).__name__
        return f"{tname}(selector={self.selector()}, value={self.value()!r})"
