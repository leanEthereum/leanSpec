set positional-arguments := true

alias help := default

# List available recipes
default:
    @just --list

# Run all quality checks (lint, format, typecheck, spellcheck, mdformat, lock)
[group('quality')]
check: lint format-check typecheck spellcheck mdformat lock-check

# Lint with ruff (no auto-fix)
[group('quality')]
lint *args:
    uv run --group lint ruff check --no-fix --show-fixes "$@"

# Format code with ruff
[group('quality')]
format *args:
    uv run --group lint ruff format "$@"

# Verify formatting with ruff (no changes)
[group('quality')]
format-check *args:
    uv run --group lint ruff format --check "$@"

# Auto-fix lint, formatting, and markdown issues
[group('quality')]
fix:
    uv run --group lint ruff check --fix
    uv run --group lint ruff format
    uv run --group docs mdformat docs/

# Type check with ty
[group('quality')]
typecheck *args:
    uv run --group lint ty check "$@"

# Spell check source, tests, packages, and docs
[group('quality')]
spellcheck *args:
    uv run --group lint codespell src tests packages docs README.md CLAUDE.md --skip="*.lock,*.svg,.git,__pycache__,.pytest_cache,tests/lean_spec/snappy/testdata" --ignore-words=.codespell-ignore-words.txt "$@"

# Verify markdown formatting in docs/
[group('quality')]
mdformat *args:
    uv run --group docs mdformat --check docs/ "$@"

# Verify uv.lock is up to date
[group('quality')]
lock-check:
    #!/usr/bin/env bash
    if ! uv lock --check; then
        echo ""
        echo "uv.lock is out of date. To sync:"
        echo "  uv lock"
        echo ""
        echo "Then commit the updated uv.lock."
        exit 1
    fi

# Run unit tests in parallel
[group('tests')]
test *args:
    uv run --group test pytest tests -n auto --maxprocesses=10 --durations=10 --dist=worksteal "$@"

# Run unit tests with coverage report (HTML + terminal)
[group('tests')]
test-cov *args:
    uv run --group test pytest --cov --cov-report=html --cov-report=term "$@"

# Run unit tests with coverage gate (fails below 80%)
[group('tests')]
test-cov-gate *args:
    uv run --group test pytest --cov --cov-report=term-missing --cov-fail-under=80 "$@"

# Run consensus-only unit tests (containers, forkchoice, networking)
[group('tests')]
test-consensus *args:
    uv run --group test pytest -n auto --maxprocesses=10 --durations=10 --dist=worksteal tests/lean_spec/subspecs/containers tests/lean_spec/subspecs/forkchoice tests/lean_spec/subspecs/networking "$@"

# Canonical CI fixture run; contributors should use `uv run fill` directly
[group('tests'), private]
fill-ci *args:
    uv run --group test fill --fork=Lstar --clean -n auto "$@"

# Run API conformance tests against an external client
[group('tests')]
apitest server_url *args:
    uv run --group test apitest "{{server_url}}" "$@"

# Run multi-node interop tests
[group('tests')]
interop *args:
    uv run --group test pytest tests/interop/ -v --no-cov --timeout=120 -x --tb=short --log-cli-level=INFO "$@"

# Build documentation site with mkdocs
[group('docs')]
docs *args:
    uv run --group docs mkdocs build "$@"

# Serve documentation locally with mkdocs (live reload)
[group('docs')]
docs-serve *args:
    uv run --group docs mkdocs serve "$@"

# Print the command to install shell completions for just recipes
[group('housekeeping')]
shell-completions:
    #!/usr/bin/env bash
    case "$(basename "$SHELL")" in
        bash)
            echo "Run the following commands to install just completions for bash:"
            echo ""
            echo "  mkdir -p ~/.local/share/bash-completion/completions"
            echo "  just --completions bash > ~/.local/share/bash-completion/completions/just"
            ;;
        zsh)
            echo "Run the following commands to install just completions for zsh:"
            echo ""
            echo "  mkdir -p ~/.zsh/completions"
            echo "  just --completions zsh > ~/.zsh/completions/_just"
            echo ""
            echo "Then add to your .zshrc:"
            echo ""
            echo "  fpath=(~/.zsh/completions \$fpath)"
            echo "  autoload -U compinit"
            echo "  compinit"
            ;;
        fish)
            echo "Run the following commands to install just completions for fish:"
            echo ""
            echo "  mkdir -p ~/.config/fish/completions"
            echo "  just --completions fish > ~/.config/fish/completions/just.fish"
            ;;
        *)
            echo "See the link below for instructions for your shell."
            ;;
    esac
    echo ""
    echo "For more details, see https://just.systems/man/en/shell-completion-scripts.html"
