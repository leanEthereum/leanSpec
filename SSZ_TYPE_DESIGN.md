# SSZ Type System Design

This document captures the design principles and implementation patterns for the leanSpec SSZ type system refactor. It serves as the single source of truth for type system decisions.

## Why This Refactor

1. **Factory patterns broke**: `Vector[T, N]` and `ByteVector[32]` syntax caused MyPy and Pydantic issues
2. **Type safety**: Eliminate all `type: ignore` comments (except for intentionally invalid test cases)
3. **First principles**: Design the cleanest possible API without backwards compatibility constraints
4. **Consistency**: Establish clear, predictable patterns across all SSZ types
5. **NO BACKWARDS COMPATIBILITY**: This is a clean slate refactor - break everything that needs breaking

## What Didn't Work

### ❌ Dynamic Class Factories
```python
# This pattern failed - MyPy couldn't understand it
Vector[Uint16, 4]
ByteVector[32]
```
**Why it failed**: Pydantic schema generation breaks, MyPy can't track types, messy implementation

### ❌ Multiple Inheritance Conflicts
```python
# This caused layout conflicts
class Uint64(int, StrictBaseModel, SSZType):
```
**Why it failed**: Can't inherit from both `int` and Pydantic models - incompatible memory layouts

## Design Principles

### Core Rule: IS-A vs HAS-A

| Type Category | Pattern | When to Use | Example |
|--------------|---------|-------------|---------|
| **Primitive** | Inherit from Python type + SSZType | Type IS a specialized primitive | `Uint64(int, SSZType)` |
| **Collection** | Inherit from SSZModel | Type HAS structured data | `SSZVector(SSZModel)` |

### Key Principles

1. **Explicit > Dynamic**: No factory functions, only explicit class definitions
2. **Natural Operations**: Primitives should behave like their Python base types
3. **Type Safety**: Full MyPy compatibility without `type: ignore`
4. **Immutability**: All SSZ types are immutable (frozen=True for models)
5. **Pydantic Validation**: Let Pydantic handle validation for complex types
6. **Break Everything**: No backwards compatibility - update all usage to new patterns

## Implementation Patterns

### Primitive Types (IS-A)

Types that ARE specialized versions of Python primitives:

```python
class BaseUint(int, SSZType):
    """Base for unsigned integers."""
    BITS: ClassVar[int]

    def __new__(cls, value: int) -> Self:
        # Validation in __new__ for immutability
        if not (0 <= value < 2**cls.BITS):
            raise OverflowError(...)
        return super().__new__(cls, value)

class Uint64(BaseUint):
    BITS = 64

# Usage - natural and intuitive
my_int = Uint64(42)
result = my_int + other  # Natural arithmetic works
```

```python
class BaseBytes(bytes, SSZType):
    """Base for fixed-length byte arrays."""
    LENGTH: ClassVar[int]

    def __new__(cls, value: Any) -> Self:
        coerced = _coerce_to_bytes(value)
        if len(coerced) != cls.LENGTH:
            raise ValueError(...)
        return super().__new__(cls, coerced)

class Bytes32(BaseBytes):
    LENGTH = 32

# Usage - behaves like bytes
my_bytes = Bytes32(b"...")
combined = my_bytes + other  # Natural concatenation
```

### Collection Types (HAS-A)

Types that HAVE structured or variable data:

```python
class SSZVector(SSZModel):
    """Fixed-length homogeneous collection."""
    ELEMENT_TYPE: ClassVar[Type[SSZType]]
    LENGTH: ClassVar[int]
    data: Tuple[SSZType, ...] = Field(...)

    @field_validator("data")
    def validate_length(cls, v):
        # Pydantic handles validation
        ...

class Uint64Vector4(SSZVector):
    ELEMENT_TYPE = Uint64
    LENGTH = 4

# Usage - keyword arguments for clarity
my_vector = Uint64Vector4(data=[1, 2, 3, 4])
```

```python
class Container(SSZModel):
    """Heterogeneous collection with named fields."""
    # Fields defined as class attributes
    slot: Uint64
    root: Bytes32

# Usage - structured data with validation
block = Container(slot=Uint64(1), root=Bytes32(b"..."))
```

### Edge Cases

**ByteList**: Variable-length bytes (0 to LIMIT)
- Semantically a collection (variable length)
- Uses SSZModel pattern like List
- NOT a primitive despite being "just bytes"

```python
class BaseByteList(SSZModel):
    LIMIT: ClassVar[int]
    data: bytes = Field(...)

class ByteList256(BaseByteList):
    LIMIT = 256
```

## Developer Experience Goals

1. **Natural Python Usage**: Primitives work like primitives
2. **Clean Type Annotations**: `my_field: Bytes32` just works
3. **Predictable Behavior**: No surprises, consistent patterns
4. **Clear Errors**: Validation errors are informative
5. **IDE Support**: Full autocomplete and type checking

## Migration Checklist

- [x] SSZVector refactored to explicit classes with SSZModel
- [x] SSZList refactored to explicit classes with SSZModel (replacing List)
- [x] BaseBytes implemented with primitive inheritance
- [x] Concrete Bytes types using BaseBytes
- [x] ByteList refactored to SSZModel pattern
- [x] All factory classes removed completely (no backwards compatibility)
- [ ] All usages updated to new explicit class patterns (BREAKING CHANGES)
- [ ] All tests updated for new constructors (data= keyword)
- [ ] MyPy fully passing without `type: ignore`

## Summary

The SSZ type system uses two clear patterns:
1. **Primitives** inherit from Python types for natural behavior
2. **Collections** use SSZModel for validation and structure

This creates a clean, type-safe, and intuitive API that leverages the best of both Python's type system and Pydantic's validation capabilities.