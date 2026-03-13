---
name: review
description: Quick-reference checklist for code review conventions in leanSpec
---

# /review - Code Review Checklist

A concise checklist distilled from CLAUDE.md for reviewing leanSpec code.

## Imports

- All imports at file top — no lazy imports inside functions
- No confusing renames — use qualified access (`x25519.X25519PublicKey`)
- `from __future__ import annotations` in every file

## Type Annotations

- Never quote annotations when `from __future__ import annotations` is present
- Prefer narrow domain types (`Bytes32`, `PeerId`, `RequestId`) over raw `bytes`
- Complete type hints on all function signatures

## Code Style

- Line length: 100 characters max
- Google docstring style
- No example code in docstrings — unit tests serve as examples
- No section separator comments (`# ====`, `# ----`)
- Module-level constants use docstrings, not comments

## Documentation

- Never use explicit function or method names in docs — names change
- Write short, scannable sentences — one idea per line
- Use bullet points or numbered lists for multiple items
- Never remove existing documentation unless directly invalidated by a code change

## Testing

- Full equality assertions — assert the whole object, not individual fields
- Descriptive test names explaining the scenario
- Use `pytest.raises(ExceptionType, match=r"...")` for error tests
- Boundary values derived from source constants, never hardcoded

## Architecture

- No backward compatibility code — no shims, aliases, or re-exports
- No unnecessary abstractions — inline is often better for spec code
- Simplicity over abstraction — readers should understand top-to-bottom
- SSZ types: domain-specific names (`Attestations`) over generic (`List4096`)

## Before Committing

```bash
uvx tox -e fix        # Auto-fix formatting
uvx tox -e all-checks # Verify all checks pass
```
