# Contributing to Lean Spec

## Quick Start

1. Fork and clone the repository
2. Install dependencies: `uv sync`
3. Make your changes
4. Run checks: `uvx tox -e all-checks`
5. Run tests: `uvx tox -e pytest`
6. Submit a pull request

## Pull Request Guidelines

1. **Create a feature branch**: `git checkout -b feat/your-feature-name`
2. **Write clear commit messages** that explain what and why
3. **Add tests** for any new functionality
4. **Update documentation** as needed
5. **Ensure all checks pass** before submitting

## Code Style

- **Type hints**: Required for all functions and methods
- **Docstrings**: Use Google style for public APIs
- **Line length**: 100 characters (enforced by ruff)
- **Formatting**: Run `uvx tox -e fix` to auto-format

## Adding New Subspecifications

New subspecs belong in `src/lean_spec/subspecs/`. Follow the pattern of existing subspecs like `poseidon2`:

```bash
mkdir -p src/lean_spec/subspecs/my_new_subspec
touch src/lean_spec/subspecs/my_new_subspec/__init__.py
mkdir -p tests/subspecs/my_new_subspec
```

## Testing

- Write tests that mirror the source structure
- Use `pytest.mark.parametrize` for multiple test cases
- Mark slow tests with `@pytest.mark.slow`

## Questions?

- Check existing [issues](https://github.com/leanEthereum/leanSpec/issues)
- Open a new issue for discussion
- See [README.md](README.md) for more details on the project structure and commands
