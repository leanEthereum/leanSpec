---
paths:
  - "**/*.py"
---

# Code Style

- Line length: 100 characters, type hints everywhere
- Google docstring style
- Test files/functions must start with `test_`
- **No example code in docstrings**: Do not include `Example:` sections with code blocks in docstrings. Keep documentation concise and focused on explaining *what* and *why*, not *how to use*. Unit tests serve as usage examples.
- **No section separator comments**: Never use banner-style separator comments (`# ====...`, `# ----...`, or similar). They add visual clutter with no value. Use blank lines to separate logical sections. If a section needs a heading, a single `#` comment line is enough.
- **No backtick references in comments or docstrings**: Never use RST/Markdown backticks (`` `` ``) to reference identifiers in Python comments or docstrings. This is source code, not rendered documentation. Backticks add visual noise and make comments harder to scan. Just write the name directly.
- **Never use RST-style double backticks**: If a backtick is used anyway (e.g. when quoting a literal value inline), use a single `` ` `` (Markdown), never `` `` `` (RST). Double backticks are banned everywhere — comments, docstrings, and any other prose embedded in Python source.
- **CRITICAL - Preserve existing documentation**: When refactoring or modifying code, NEVER remove or rewrite existing comments and docstrings unless they are directly invalidated by the code change. Removing documentation that still applies creates unnecessary noise in code review diffs and destroys context that was carefully written. Only modify documentation when:
  - The documented behavior has actually changed
  - The comment references code that no longer exists
  - The comment is factually wrong after your change

## Import Style

**All imports must be at the top of the file.** Never place imports inside functions, methods, or conditional blocks. This applies to both source code and tests. The **only** exception is genuine circular dependencies — in that case, import inside the function that needs the type (see the `TYPE_CHECKING` rule below).

Bad:
```python
def process(data):
    from lean_spec.subspecs.ssz import hash_tree_root
    return hash_tree_root(data)
```

Good:
```python
from lean_spec.subspecs.ssz import hash_tree_root

def process(data):
    return hash_tree_root(data)
```

**Avoid confusing import renames.** When an external library exports a name that conflicts with a local type, prefer restructuring over renaming.

Bad:
```python
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey as CryptographyX25519PublicKey,
)
```

Good - import the module and use qualified access:
```python
from cryptography.hazmat.primitives.asymmetric import x25519

# Then use x25519.X25519PublicKey when needed
public_key = x25519.X25519PublicKey.from_public_bytes(data)
```

Good - move conflicting local types to a separate constants/types module:
```python
# In constants.py - no external dependencies that conflict
X25519PublicKey: TypeAlias = Bytes32

# In crypto.py - import from constants, use qualified access for external
from .constants import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import x25519
```

This keeps code readable and avoids mental overhead of tracking renamed imports.

**CRITICAL - Never use `TYPE_CHECKING`.** The `if TYPE_CHECKING:` pattern is banned entirely from this codebase. Do not import `TYPE_CHECKING` from `typing`, and do not place any imports behind `if TYPE_CHECKING:` guards. This pattern is fragile, hard to maintain, and causes subtle bugs — especially with Pydantic models.

Instead:

- **No circular dependency?** Just import normally at the top of the file. Most guarded imports have no actual cycle.
- **Genuine circular dependency?** Import inside the function that needs it. This is the **only** exception to the top-level import rule. Keep the local import as close as possible to where it's used.
- **Forward references needed?** Use quoted strings (`"ClassName"`) in annotations, or add `from __future__ import annotations` (but NOT in Pydantic model files).

Bad:
```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lean_spec.subspecs.forkchoice import Store

def process(store: "Store") -> None: ...
```

Good:
```python
from lean_spec.subspecs.forkchoice import Store

def process(store: Store) -> None: ...
```

Good (local import for genuine circular dependency):
```python
def verify_signatures(self, state: "State") -> bool:
    from ..state import State

    # use State here
    ...
```

## Type Annotations

**Never quote type annotations when `from __future__ import annotations` is present.** With future annotations, all annotations are already lazy strings. Adding quotes is redundant and noisy.

Bad:
```python
from __future__ import annotations

def create(cls) -> "Store":
    ...
```

Good:
```python
from __future__ import annotations

def create(cls) -> Store:
    ...
```

The only valid use of quoted annotations is in files that do NOT have `from __future__ import annotations` and need a forward reference. Prefer adding the future import instead.

**Prefer narrow domain types over raw builtins.** Use `Bytes32`, `Bytes33`, `Bytes52` etc. instead of `bytes` in signatures. Spec code should never accept or return `bytes` when a more specific type exists.

## Module-Level Constants

Use docstrings (not comments) to document module-level constants. Place the docstring immediately after the assignment.

Bad:
```python
# Noise protocol name - used to initialize the handshake state
# This is the full protocol name per the Noise spec
PROTOCOL_NAME: bytes = b"Noise_XX_25519_ChaChaPoly_SHA256"
```

Good:
```python
PROTOCOL_NAME: bytes = b"Noise_XX_25519_ChaChaPoly_SHA256"
"""Noise protocol name per the Noise spec. Used to initialize the handshake state."""
```

This pattern:
- Is recognized by documentation tools (Sphinx, mkdocs)
- Shows up in IDE tooltips and autocomplete
- Keeps documentation close to the code it describes

