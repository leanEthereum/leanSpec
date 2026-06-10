# Development Workflow

## Running Tests

```bash
uv sync                           # Install dependencies
uv run pytest                     # Run unit tests
uv run fill --fork=lstar --clean -n auto                # Generate test vectors
uv run fill --fork=lstar --clean -n auto --scheme=prod  # Generate test vectors with production scheme
```

## Code Quality

```bash
just format     # Format code
just fix        # Auto-fix lint, formatting, and markdown
just typecheck  # Type check
just check      # All quality checks (lint, format, typecheck, spell, mdformat, lock)
just            # List all available recipes
```

## Common Tasks

- **Main specs**: `src/lean_spec/`
- **Unit tests**: `tests/` (mirrors source structure)
- **Consensus spec tests**: `tests/consensus/` (generates test vectors)

