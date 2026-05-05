---
name: workflows
description: Common developer workflows, commands, and troubleshooting for leanSpec
---

# /workflows - Repository Workflows

Common developer workflows and commands for working in leanSpec.

## Running Specific Tests

```bash
# Single test file
just test tests/lean_spec/subspecs/networking/discovery/test_transport.py -v

# Single test class or method
just test -k "TestDiscoveryTransport::test_start" -v

# With print output visible
just test -s -k "test_name"
```

## Resolving Type Errors

The project uses two type checkers. Run them separately to isolate issues:

```bash
# Full type check (ty — the primary checker used in CI)
just typecheck

# Lint check (ruff — catches style and import issues)
just lint
```

Common type error patterns:
- `invalid-assignment` — Wrong type assigned; check if a domain type (`RequestId`, `PeerId`) is expected instead of raw `bytes`
- `invalid-argument-type` — Function argument type mismatch; verify the function signature
- `union-attr` — Accessing attribute on a possibly-`None` value; add an `assert is not None` guard

## Inspecting Coverage

After running tests, coverage reports are generated:

```bash
# View coverage in terminal
just test-cov

# Open HTML report
open htmlcov/index.html
```

## Running Interop Tests

Interop tests are excluded from the default test run. Run them explicitly:

```bash
just interop
```

## Spell Check Failures

```bash
# Run spell check
just spellcheck

# Add legitimate words to the ignore list
echo "newword" >> .codespell-ignore-words.txt
```

## Markdown Formatting

```bash
# Check markdown formatting (docs only)
just mdformat
```

## Common Pitfalls

- **Tests pass locally but CI fails**: CI runs checks across Python 3.12, 3.13, and 3.14. Ensure no version-specific syntax is used.
- **`ruff format` changes after `ruff check --fix`**: Always run format after fix — the fixer doesn't guarantee formatting compliance.
- **Import ordering issues**: Run `just fix` to auto-sort imports.
