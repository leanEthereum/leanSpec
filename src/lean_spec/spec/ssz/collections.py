"""
SSZ vector and list collections.

Two sequence shapes are defined by the SSZ spec:

- A vector holds exactly LENGTH elements of one declared type.
- A list holds between zero and LIMIT elements of one declared type.

A type is fixed-size when every value encodes to the same number of bytes.
A variable-size type allows different values to encode to different widths.

The encoding shape follows from the element type:

- Fixed-size elements share one known width.
  Bodies pack back-to-back with no separator.

- Variable-size elements are prefixed by a uint32 offset table.
  Each offset is a byte position from the start of the sequence.
  It points at the start of one encoded element body.

The offset table takes 4 * N bytes for N elements.
The first offset therefore equals 4 * N — the byte position right after the table.

For example, three variable-size bodies of widths 5, 3, and 7 encode to 27 bytes:

    bytes 0..3   : off_0 = 12   (first body starts at byte 12)
    bytes 4..7   : off_1 = 17   (second body starts at byte 17)
    bytes 8..11  : off_2 = 20   (third body starts at byte 20)
    bytes 12..16 : body_0       (5 bytes)
    bytes 17..19 : body_1       (3 bytes)
    bytes 20..26 : body_2       (7 bytes)
"""

import io
from collections.abc import Iterator, Sequence
from itertools import pairwise
from typing import (
    IO,
    Any,
    ClassVar,
    Self,
    cast,
    overload,
    override,
)

from pydantic import Field, field_serializer, field_validator

from .byte_arrays import BaseBytes
from .exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from .ssz_base import BYTES_PER_LENGTH_OFFSET, SSZModel, SSZType
from .uint import Uint32


def _validate_offsets(offsets: list[int], scope: int, type_name: str) -> None:
    """
    Enforce the offset-table invariants before reading element bodies.

    Two rules imply that every (start, end) pair is valid:

    - Offsets are monotonically non-decreasing, so no body has negative width.
    - The final offset stays within scope, so no body reads past its budget.

    Raises:
        SSZSerializationError: When a later offset is smaller than an earlier one.
        SSZSerializationError: When the final offset exceeds the available scope.
    """
    # Empty sequences have no bodies and therefore no boundaries to enforce.
    if not offsets:
        return

    # Pairwise comparison catches any decreasing step in the table.
    for previous, current in pairwise(offsets):
        if current < previous:
            raise SSZSerializationError(
                f"{type_name}: offsets not monotonically increasing: {previous} -> {current}"
            )

    # The final boundary is the scope appended by the decoder.
    # A larger final offset would extend past the available bytes.
    if offsets[-1] > scope:
        raise SSZSerializationError(
            f"{type_name}: final offset {offsets[-1]} exceeds scope {scope}"
        )


class _SSZSequence[T: SSZType](SSZModel):
    """
    Shared scaffolding for fixed- and variable-length SSZ sequences.

    Two subclasses concretize this base:

    - A vector pins the element count at LENGTH.
    - A list bounds the element count by LIMIT.

    Both store elements in a Pydantic field named data.
    Both expose tuple-style iteration and indexing.
    Both share the offset-table writer used by variable-size encodings.

    The element type is inferred from the generic parameter, once per subclass.
    """

    ELEMENT_TYPE: ClassVar[type[SSZType]]
    """SSZ type of every element, inferred from the generic parameter."""

    data: Sequence[T] = Field(default_factory=tuple)
    """
    Immutable sequence of elements.

    Accepts lists, tuples, or iterables of compatible values on input.
    Stored as an immutable tuple after validation.
    """

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """
        Read the element type from the generic parameter in a class declaration.

        When a subclass is written as:

            class Uint16Vector2(SSZVector[Uint16]):
                LENGTH = 2

        the Uint16 inside the brackets is copied into Uint16Vector2.ELEMENT_TYPE.
        This way, a user does not have to write ELEMENT_TYPE = Uint16 by hand.
        """
        super().__init_subclass__(**kwargs)
        if "ELEMENT_TYPE" in cls.__dict__:
            return

        # Walk direct parents looking for a parameterized SSZ sequence base.
        # The first concrete element type wins.
        # Layers carrying only a TypeVar are skipped.
        for base in cls.__bases__:
            # Pydantic stores the generic parameterization on every generic parent.
            # An empty default skips bases that were never made generic.
            metadata = getattr(base, "__pydantic_generic_metadata__", {})

            # Origin is the unparameterized class — for example SSZVector itself.
            # Skip bases outside the sequence hierarchy.
            origin = metadata.get("origin")
            if not (isinstance(origin, type) and issubclass(origin, _SSZSequence)):
                continue

            # Args holds the types that appeared between the brackets.
            # A real SSZType subclass wins.
            # A bare TypeVar means an abstract layer has not bound the parameter yet.
            for arg in metadata.get("args", ()):
                if isinstance(arg, type) and issubclass(arg, SSZType):
                    cls.ELEMENT_TYPE = arg
                    return

    @field_serializer("data", when_used="json")
    def _serialize_data(self, value: Sequence[T]) -> list[Any]:
        """
        Render the elements as a JSON-friendly list.

        Two leaf shapes need bespoke handling:

        - Byte arrays render as 0x-prefixed hex strings.
        - Integer leaves (uints, field elements) flatten to a plain int.

        Anything else passes through for Pydantic's downstream serializers.
        """
        # Pydantic does not auto-flatten SSZ leaf types into JSON primitives.
        # Each element is inspected and rewritten according to the rules below.
        result: list[Any] = []
        for item in value:
            # Byte-array leaves render as 0x-prefixed hex strings.
            # This matches how every other byte value appears in spec output.
            if isinstance(item, BaseBytes):
                result.append("0x" + item.hex())

            # Integer leaves (uints, field elements) flatten to a plain int.
            # Bool also subclasses int.
            # It is excluded so True and False survive in JSON unchanged.
            elif isinstance(item, int) and not isinstance(item, bool):
                result.append(int(item))

            # Anything else passes through for Pydantic's downstream serializers.
            # Nested containers, booleans, strings, and primitive values land here.
            else:
                result.append(item)
        return result

    def _write_variable_payload(self, stream: IO[bytes], offset_count: int) -> int:
        """
        Write the offset table followed by the buffered element bodies.

        Offsets are emitted to the output stream first.
        Bodies are buffered and flushed after the table.

        Args:
            stream: Output binary stream.
            offset_count: Number of offset entries in the table.

        Returns:
            Total bytes written, equal to the final offset value.
        """
        # A forward-only stream cannot revisit earlier offset slots to fix them up.
        # Bodies must be buffered until the table is fully written.
        bodies = io.BytesIO()

        # The first offset points past the entire offset table.
        # Each subsequent offset advances by the previous body's width.
        offset = offset_count * BYTES_PER_LENGTH_OFFSET
        for element in self.data:
            Uint32(offset).serialize(stream)
            offset += element.serialize(bodies)

        # Bodies land at the byte positions the offsets just declared.
        stream.write(bodies.getvalue())
        return offset

    @override
    def __len__(self) -> int:
        """Return the number of elements in the sequence."""
        return len(self.data)

    @override
    def __iter__(self) -> Iterator[T]:  # type: ignore[override]
        """
        Iterate over the elements.

        Defined explicitly because the parent Pydantic model otherwise yields
        name/value pairs of its fields.
        """
        return iter(self.data)

    @overload
    def __getitem__(self, index: int) -> T: ...
    @overload
    def __getitem__(self, index: slice) -> Sequence[T]: ...

    def __getitem__(self, index: int | slice) -> T | Sequence[T]:
        """Index by integer or slice the underlying tuple."""
        return self.data[index]

    @property
    def elements(self) -> list[T]:
        """Return a mutable copy of the elements as a list."""
        return list(self.data)


class SSZVector[T: SSZType](_SSZSequence[T]):
    """
    Fixed-length, immutable SSZ sequence.

    Holds exactly LENGTH elements of one declared type.
    The element count is pinned at the type level and never changes at runtime.

    Two encoding shapes follow from the element type:

    - Fixed-size elements pack back-to-back with no separators.
    - Variable-size elements use the offset-table layout.

    Subclasses declare LENGTH directly in the class body.
    The element type is inferred from the generic parameter.

    For example, three Uint16 values encode as six raw bytes:

        bytes 0..1 : 67 45   (= 0x4567, little-endian)
        bytes 2..3 : 23 01   (= 0x0123)
        bytes 4..5 : ef cd   (= 0xCDEF)

    Two variable-size bodies of widths 5 and 7 encode to 20 bytes:

        bytes 0..3   : off_0 = 8    (first body starts at byte 8)
        bytes 4..7   : off_1 = 13   (second body starts at byte 13)
        bytes 8..12  : body_0       (5 bytes)
        bytes 13..19 : body_1       (7 bytes)
    """

    LENGTH: ClassVar[int]
    """Exact number of elements, fixed at the type level."""

    @field_validator("data", mode="before")
    @classmethod
    def _coerce_and_validate(cls, v: Any) -> tuple[SSZType, ...]:
        """
        Enforce the exact element count and coerce inputs into ELEMENT_TYPE.

        Three rejections happen before coercion:

        - Misconfigured subclasses without ELEMENT_TYPE or LENGTH fail.
        - String and bytes inputs are rejected to avoid silent character iteration.
        - Non-iterable inputs fail fast with a descriptive message.

        Each element passes through the declared type's constructor on coercion.
        Failures re-raise with the high-level expectation in the message.
        The chained cause preserves the underlying coercion detail.
        """
        # Subclasses must declare both annotations before any instance can validate.
        if not hasattr(cls, "ELEMENT_TYPE") or not hasattr(cls, "LENGTH"):
            raise SSZTypeError(f"{cls.__name__} must define ELEMENT_TYPE and LENGTH")

        # Accept the natural input shapes:
        #
        #   - list or tuple    pass through directly.
        #   - other iterables  materialize into a list so the length check works.
        #   - str or bytes     rejected — iterating yields characters or ints.
        if isinstance(v, (list, tuple)):
            items: Sequence[Any] = v
        elif isinstance(v, (str, bytes, bytearray)):
            raise SSZTypeError(
                f"{cls.__name__}: Expected iterable of {cls.ELEMENT_TYPE.__name__}, "
                f"got {type(v).__name__}"
            )
        elif hasattr(v, "__iter__"):
            items = list(v)
        else:
            raise SSZTypeError(f"{cls.__name__}: Expected iterable, got {type(v).__name__}")

        # Fixed-length type: the input must contain exactly LENGTH elements.
        if len(items) != cls.LENGTH:
            raise SSZValueError(
                f"{cls.__name__} requires exactly {cls.LENGTH} elements, got {len(items)}"
            )

        # Coerce each non-typed element through the declared element type.
        # Inner errors are re-raised with the high-level expectation.
        # The chained cause preserves the underlying coercion detail.
        result: list[SSZType] = []
        for item in items:
            if isinstance(item, cls.ELEMENT_TYPE):
                result.append(item)
                continue
            try:
                result.append(cast(Any, cls.ELEMENT_TYPE)(item))
            except (SSZTypeError, SSZValueError, TypeError, ValueError) as e:
                raise SSZTypeError(
                    f"Expected {cls.ELEMENT_TYPE.__name__}, got {type(item).__name__}: {e}"
                ) from e
        return tuple(result)

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """A vector is fixed-size if and only if its elements are fixed-size."""
        return cls.ELEMENT_TYPE.is_fixed_size()

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """
        Return the fixed encoded byte length.

        Raises:
            SSZTypeError: When the element type is variable-size.
        """
        if not cls.is_fixed_size():
            raise SSZTypeError(f"{cls.__name__}: variable-size vector has no fixed byte length")
        return cls.ELEMENT_TYPE.get_byte_length() * cls.LENGTH

    @override
    def serialize(self, stream: IO[bytes]) -> int:
        """Write the SSZ encoding to a binary stream and return the byte count."""
        # Fixed-size elements: serialize each body directly, no offsets needed.
        if self.is_fixed_size():
            return sum(element.serialize(stream) for element in self.data)
        # Variable-size elements: emit a table of LENGTH offsets, then the bodies.
        return self._write_variable_payload(stream, self.LENGTH)

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Read one vector from a binary stream within the given byte budget.

        Two cases mirror the encoder:

        - Fixed-size elements: scope equals LENGTH times the element byte width.
        - Variable-size elements: a LENGTH-wide offset table precedes the bodies.

        Raises:
            SSZSerializationError: When scope or any offset is inconsistent.
        """
        # Fixed-size case: elements pack back-to-back at a known stride.
        # The byte budget must match LENGTH times the element width exactly.
        if cls.is_fixed_size():
            element_byte_length = cls.ELEMENT_TYPE.get_byte_length()
            expected_total = element_byte_length * cls.LENGTH
            if scope != expected_total:
                raise SSZSerializationError(
                    f"{cls.__name__}: expected {expected_total} bytes, got {scope}"
                )
            elements = [
                cls.ELEMENT_TYPE.deserialize(stream, element_byte_length) for _ in range(cls.LENGTH)
            ]
            return cls(data=elements)

        # Variable-size case: read the full offset table, then slice each body.
        #
        # Scope must cover at least the offset table itself.
        # The first offset must then equal the table's own byte width.
        # Scope is appended as the final boundary so pairwise iteration yields every span.
        expected_first = cls.LENGTH * BYTES_PER_LENGTH_OFFSET
        if scope < expected_first:
            raise SSZSerializationError(
                f"{cls.__name__}: scope {scope} too small, expected at least {expected_first}"
            )
        offsets = [
            int(Uint32.deserialize(stream, BYTES_PER_LENGTH_OFFSET)) for _ in range(cls.LENGTH)
        ]
        if offsets[0] != expected_first:
            raise SSZSerializationError(
                f"{cls.__name__}: invalid offset {offsets[0]}, expected {expected_first}"
            )
        offsets.append(scope)
        _validate_offsets(offsets, scope, cls.__name__)

        return cls(
            data=[
                cls.ELEMENT_TYPE.deserialize(stream, end - start)
                for start, end in pairwise(offsets)
            ]
        )


class SSZList[T: SSZType](_SSZSequence[T]):
    """
    Variable-length SSZ sequence with a maximum capacity.

    Holds between zero and LIMIT elements of one declared type.
    The element count is set at construction time and varies between instances.

    Two encoding shapes mirror the vector cases:

    - Fixed-size elements pack back-to-back, count recovered from wire scope.
    - Variable-size elements use an offset table that also reveals the count.

    The hash tree root mixes in the element count alongside the chunked data.
    Two lists with identical contents but different LIMITs hash differently.

    Subclasses declare LIMIT directly in the class body.
    The element type is inferred from the generic parameter.

    For example, three Uint16 values under a limit of eight encode as six bytes:

        bytes 0..1 : bb aa   (= 0xAABB, little-endian, no length prefix)
        bytes 2..3 : ad c0   (= 0xC0AD)
        bytes 4..5 : ff ee   (= 0xEEFF)

    Two variable-size bodies of widths 4 and 6 encode to 18 bytes:

        bytes 0..3   : off_0 = 8    (first body starts at byte 8)
        bytes 4..7   : off_1 = 12   (second body starts at byte 12)
        bytes 8..11  : body_0       (4 bytes)
        bytes 12..17 : body_1       (6 bytes)
    """

    LIMIT: ClassVar[int]
    """Maximum number of elements allowed."""

    @field_validator("data", mode="before")
    @classmethod
    def _coerce_and_validate(cls, v: Any) -> tuple[SSZType, ...]:
        """
        Enforce the maximum element count and coerce inputs into ELEMENT_TYPE.

        Three rejections happen before coercion:

        - Misconfigured subclasses without ELEMENT_TYPE or LIMIT fail.
        - String and bytes inputs are rejected to avoid silent character iteration.
        - Non-iterable inputs fail fast with a descriptive message.

        Each element passes through the declared type's constructor on coercion.
        Failures re-raise with the high-level expectation in the message.
        The chained cause preserves the underlying coercion detail.
        """
        # Subclasses must declare both annotations before any instance can validate.
        if not hasattr(cls, "ELEMENT_TYPE") or not hasattr(cls, "LIMIT"):
            raise SSZTypeError(f"{cls.__name__} must define ELEMENT_TYPE and LIMIT")

        # Accept the natural input shapes:
        #
        #   - list or tuple    pass through directly.
        #   - other iterables  materialize into a list so the length check works.
        #   - str or bytes     rejected — iterating yields characters or ints.
        if isinstance(v, (list, tuple)):
            items: Sequence[Any] = v
        elif isinstance(v, (str, bytes, bytearray)):
            raise SSZTypeError(
                f"{cls.__name__}: Expected iterable of {cls.ELEMENT_TYPE.__name__}, "
                f"got {type(v).__name__}"
            )
        elif hasattr(v, "__iter__"):
            items = list(v)
        else:
            raise SSZTypeError(f"{cls.__name__}: Expected iterable, got {type(v).__name__}")

        # Variable-length type: any count is fine, up to LIMIT.
        if len(items) > cls.LIMIT:
            raise SSZValueError(f"{cls.__name__} exceeds limit of {cls.LIMIT}, got {len(items)}")

        # Coerce each non-typed element through the declared element type.
        # Inner errors are re-raised with the high-level expectation.
        # The chained cause preserves the underlying coercion detail.
        result: list[SSZType] = []
        for item in items:
            if isinstance(item, cls.ELEMENT_TYPE):
                result.append(item)
                continue
            try:
                result.append(cast(Any, cls.ELEMENT_TYPE)(item))
            except (SSZTypeError, SSZValueError, TypeError, ValueError) as e:
                raise SSZTypeError(
                    f"Expected {cls.ELEMENT_TYPE.__name__}, got {type(item).__name__}: {e}"
                ) from e
        return tuple(result)

    def __add__(self, other: Any) -> Self:
        """
        Concatenate with another sequence and return a new list.

        The validator on the resulting instance enforces LIMIT.
        Overflowing concatenations raise SSZValueError at construction.
        """
        match other:
            case SSZList():
                new_data = (*self.data, *other.data)
            case list() | tuple():
                new_data = (*self.data, *other)
            case _:
                return NotImplemented
        return type(self)(data=new_data)

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """A list is never fixed-size since the element count ranges from zero to LIMIT."""
        return False

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """
        Variable-size types have no fixed byte length.

        Raises:
            SSZTypeError: Always — call this only on fixed-size types.
        """
        raise SSZTypeError(f"{cls.__name__}: variable-size list has no fixed byte length")

    @override
    def serialize(self, stream: IO[bytes]) -> int:
        """Write the SSZ encoding to a binary stream and return the byte count."""
        # Fixed-size elements pack back-to-back with no length prefix.
        # The element count is recovered on decode from the wire scope.
        if self.ELEMENT_TYPE.is_fixed_size():
            return sum(element.serialize(stream) for element in self.data)
        # Variable-size elements: emit a table sized for the runtime count, then bodies.
        return self._write_variable_payload(stream, len(self.data))

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Read one list from a binary stream within the given byte budget.

        Three cases cover all valid inputs:

        - Empty scope decodes to an empty list.
        - Fixed-size elements: count equals scope divided by element width.
        - Variable-size elements: the first offset locates bodies and reveals the count.

        Raises:
            SSZSerializationError: When scope or any offset is malformed.
            SSZValueError: When the recovered element count exceeds LIMIT.
        """
        # Empty case: any zero-byte payload decodes to an empty list.
        if scope == 0:
            return cls(data=())

        # Fixed-size case: elements pack back-to-back at a known stride.
        # The count is recovered by dividing the byte budget by the element width.
        if cls.ELEMENT_TYPE.is_fixed_size():
            element_size = cls.ELEMENT_TYPE.get_byte_length()
            if scope % element_size != 0:
                raise SSZSerializationError(
                    f"{cls.__name__}: scope {scope} not divisible by element size {element_size}"
                )
            num_elements = scope // element_size
            if num_elements > cls.LIMIT:
                raise SSZValueError(
                    f"{cls.__name__} exceeds limit of {cls.LIMIT}, got {num_elements}"
                )
            elements = [
                cls.ELEMENT_TYPE.deserialize(stream, element_size) for _ in range(num_elements)
            ]
            return cls(data=elements)

        # Variable-size case: the first offset reveals both where bodies begin
        # and the element count (the offset width divides the table width).
        if scope < BYTES_PER_LENGTH_OFFSET:
            raise SSZSerializationError(
                f"{cls.__name__}: scope {scope} too small for variable-size list"
            )
        first_offset = int(Uint32.deserialize(stream, BYTES_PER_LENGTH_OFFSET))
        if first_offset > scope or first_offset % BYTES_PER_LENGTH_OFFSET != 0:
            raise SSZSerializationError(f"{cls.__name__}: invalid offset {first_offset}")
        count = first_offset // BYTES_PER_LENGTH_OFFSET
        if count > cls.LIMIT:
            raise SSZValueError(f"{cls.__name__} exceeds limit of {cls.LIMIT}, got {count}")

        # Read the remaining offsets, append scope as the final boundary,
        # then pairwise-iterate the boundary list to yield each body's byte span.
        offsets = [
            first_offset,
            *(int(Uint32.deserialize(stream, BYTES_PER_LENGTH_OFFSET)) for _ in range(count - 1)),
            scope,
        ]
        _validate_offsets(offsets, scope, cls.__name__)

        return cls(
            data=[
                cls.ELEMENT_TYPE.deserialize(stream, end - start)
                for start, end in pairwise(offsets)
            ]
        )
