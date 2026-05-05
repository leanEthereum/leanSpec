# Development Workflow

## Running Tests

```bash
uv sync                           # Install dependencies
uv run pytest                     # Run unit tests
uv run fill --fork=lstar --clean -n auto                # Generate test vectors
uv run fill --fork=lstar --clean -n auto --scheme=prod  # Generate test vectors with production scheme
# Note: execution layer support is planned for future, infrastructure is ready
# for now, `--layer=consensus` is default and the only value used.
```

## Code Quality

```bash
uv run ruff format       # Format code
uv run ruff check --fix  # Lint and fix
uvx tox -e typecheck     # Type check
uvx tox -e all-checks    # All quality checks
uvx tox                  # Everything (checks + tests + docs)
```

## Common Tasks

- **Main specs**: `src/lean_spec/`
- **Subspecs**: `src/lean_spec/subspecs/{subspec}/`
- **Unit tests**: `tests/lean_spec/` (mirrors source structure)
- **Consensus spec tests**: `tests/consensus/` (generates test vectors)
- **Execution spec tests**: `tests/execution/` (future - infrastructure ready)

