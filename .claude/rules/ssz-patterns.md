---
paths:
  - "src/lean_spec/subspecs/containers/**/*.py"
  - "src/lean_spec/types/**/*.py"
---

# SSZ Type Design Patterns

When creating SSZ types, follow these established patterns:

## Domain-Specific Types (Preferred)

- Use meaningful names that describe the purpose: `JustificationValidators`, `HistoricalBlockHashes`, `Attestations`
- Define domain-specific types in modular structure (see Architecture section below)
- Avoid generic names with numbers like `Bitlist68719476736` or `SignedAttestationList4096`

## SSZType vs SSZModel Design Decision

**SSZType (IS-A pattern)**: Use for types that *are* data

- Primitive scalars: `Uint64`, `Boolean`, `Bytes32`
- These inherit directly from their underlying Python types
- Example: `Uint64(42)` *is* the integer 42 with SSZ serialization

**SSZModel (HAS-A pattern)**: Use for types that *have* data

- Collections: `SSZList`, `SSZVector`, bitfields
- Containers: `State`, `Block`, etc.
- These use Pydantic models with a `data` field for contents
- Example: `MyList(data=[1, 2, 3])` *has* a list of data with SSZ serialization

**Key principle**: If the type conceptually *holds* or *contains* other data, use SSZModel for consistent validation and immutability.

## Modular Architecture

Containers should be organized into modules with clear separation:

```
src/lean_spec/subspecs/containers/
├── state/
│   ├── __init__.py      # Exports State and related types
│   ├── state.py         # Main State container class
│   └── types.py         # State-specific types: JustifiedSlots, HistoricalBlockHashes, etc.
├── block/
│   ├── __init__.py      # Exports Block classes
│   ├── block.py         # Main Block container classes
│   └── types.py         # Block-specific types: Attestations, etc.
└── ...
```

**Key principles:**

- **Base types** (BaseBitlist, SSZList, etc.) stay in general scope (`src/lean_spec/types/`)
- **Spec-specific types** go in their respective modules (`state/types.py`, `block/types.py`)
- **Public API** exposed through `__init__.py` files for backward compatibility
- **Domain-specific types** defined close to where they're used

## Examples

**Good domain-specific types:**

```python
# In state/types.py
HISTORICAL_ROOTS_LIMIT = 262144

class JustificationValidators(BaseBitlist):
    """Bitlist for tracking validator justifications."""
    LIMIT = HISTORICAL_ROOTS_LIMIT * HISTORICAL_ROOTS_LIMIT

# In block/types.py
class Attestations(SSZList):
    """List of signed attestations included in a block."""
    ELEMENT_TYPE = SignedAttestation
    LIMIT = 4096  # VALIDATOR_REGISTRY_LIMIT
```

**Avoid generic types:**

```python
# Don't do this:
class Bitlist68719476736(BaseBitlist): ...
class SignedAttestationList4096(SSZList): ...
```

