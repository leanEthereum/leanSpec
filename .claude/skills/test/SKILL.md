---
name: test
description: Run unit tests with coverage
---

# /test - Run Unit Tests

Run pytest unit tests.

## Default

```bash
uvx tox -e pytest
```

## Options

Pass additional arguments after `--`:

- `/test -- -v` - Verbose output
- `/test -- -k "test_serialize"` - Run matching tests
- `/test -- tests/lean_spec/subspecs/ssz/` - Run specific test directory

## Examples

- `/test` - Run all unit tests
- `/test -- --cov` - Run with coverage report
