# Contributing to Lean Spec

## Quick Start

1. Fork and clone the repository
2. Install dependencies: `uv sync`
3. Make your changes
4. Install `just`: `uv tool install just-bin`
5. Run checks: `just check`
6. Run tests: `just test`
7. Submit a pull request

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
- **Formatting**: Run `just fix` to auto-format

## Adding New Subspecifications

Cryptographic subspecs live under `src/lean_spec/spec/crypto/`. Follow the pattern of an existing one like the `xmss` package:

```bash
mkdir -p src/lean_spec/spec/crypto/my_new_subspec
touch src/lean_spec/spec/crypto/my_new_subspec/__init__.py
mkdir -p tests/spec/crypto/my_new_subspec
```

Tests mirror the source layout one-to-one (see `tests/spec/crypto/xmss/`).

## Testing

- Write tests that mirror the source structure
- Use `pytest.mark.parametrize` for multiple test cases
- Mark slow tests with `@pytest.mark.slow`

## Questions?

- Check existing [issues](https://github.com/leanEthereum/leanSpec/issues)
- Open a new issue for discussion
- See [README.md](README.md) for more details on the project structure and commands
