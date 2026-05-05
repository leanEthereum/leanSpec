# Working with leanSpec

## Repository Overview

This is a Python repository for the Lean Ethereum Python specifications. It is set up as
a single `uv` project containing the main specifications and various cryptographic
subspecifications that the Lean Ethereum protocol relies on.

## Key Directories

- `src/lean_spec/` - Main specifications for the Lean Ethereum protocol
- `src/lean_spec/subspecs/` - Supporting subspecifications for cryptographic primitives
- `tests/` - Specification tests
- `docs/` - MkDocs documentation source

## Important Notes

- Python 3.12+ required
- Use Pydantic models for validation
- Keep specs simple, readable, and clear
- Repository is `leanSpec` not `lean-spec`
- **Always run linter checks before finishing**: Run `uvx tox -e all-checks` at the end of any code changes to ensure all linting, formatting, type checking, and spell checking passes.
- **CRITICAL - NO BACKWARD COMPATIBILITY**: This is a STRICT requirement. NEVER add backward compatibility code under any circumstances. This means:
  - NO legacy constants (like `KEY_TYPE_ED25519 = KeyType.ED25519`)
  - NO wrapper functions that delegate to new classes
  - NO re-exports of deprecated APIs
  - NO deprecation shims or aliases
  - When refactoring from functions to classes, DELETE the old functions entirely
  - Update ALL call sites to use the new API directly
  - Old patterns must be REMOVED, not preserved alongside new ones
