---
name: checks
description: Run all code quality checks
---

# /checks - Run All Quality Checks

Run the complete quality check suite.

## Command

```bash
uvx tox -e all-checks
```

## What It Runs

1. `ruff check` - Linting
2. `ruff format --check` - Formatting
3. `ty check` - Type checking
4. `codespell` - Spell checking
5. `mdformat` - Markdown formatting

## When to Use

Run this before committing changes to ensure code quality standards are met.
This is the same check that runs in CI.
