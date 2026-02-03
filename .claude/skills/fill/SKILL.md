---
name: fill
description: Generate consensus layer test fixtures
---

# /fill - Generate Test Fixtures

Run the test filler to generate consensus layer test fixtures.

## Default Usage

```bash
uvx tox -e fill
```

## Options

Pass additional arguments after `--`:

- `/fill -- --fork=Electra` - Generate for Electra fork
- `/fill -- path/to/test.py` - Generate fixtures for specific test file

## What It Does

Runs `fill --fork=Devnet --clean -n auto` via tox, which:

1. Discovers tests in `tests/consensus/`
2. Executes spec tests to generate fixtures
3. Outputs JSON fixtures to `fixtures/consensus/`
