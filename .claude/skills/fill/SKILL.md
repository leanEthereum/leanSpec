---
name: fill
description: Generate consensus layer test fixtures
---

# /fill - Generate Test Fixtures

Run the test filler to generate consensus layer test fixtures.

## Default Usage

```bash
uv run fill --fork=Lstar --clean -n auto
```

## Options

Pass additional arguments after `--`:

- `/fill -- --scheme=prod` - Use production signature scheme (slower)
- `/fill -- --fork=<other>` - Generate for a different fork
- `/fill -- path/to/test.py` - Generate fixtures for specific test file

## What It Does

1. Discovers tests in `tests/consensus/`
2. Executes spec tests to generate fixtures
3. Outputs JSON fixtures to `fixtures/consensus/`

The `just fill-ci` recipe wraps the same command for CI; contributors should
invoke `uv run fill` directly so flags like `--fork` and `--clean` stay visible.
