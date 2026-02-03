---
name: fix
description: Auto-fix linting and formatting issues
---

# /fix - Auto-Fix Code Quality Issues

Automatically fix linting and formatting issues.

## Command

```bash
uvx tox -e fix
```

## What It Fixes

1. Import sorting (isort rules)
2. Code formatting (black-compatible)
3. Simple lint errors (auto-fixable)

## When to Use

Run this after making code changes to automatically fix formatting issues.
Then run `/checks` to verify all issues are resolved.
