set positional-arguments := true

alias help := default

[default]
default:
    @just --list

[group('quality')]
check: lint typecheck spellcheck mdformat

[group('quality')]
lint *args:
    uv run --group lint ruff check --no-fix --show-fixes "$@"

[group('quality')]
format *args:
    uv run --group lint ruff format "$@"

[group('quality')]
fix:
    uv run --group lint ruff check --fix
    uv run --group lint ruff format
    uv run --group docs mdformat docs/

[group('quality')]
typecheck *args:
    uv run --group lint ty check "$@"

[group('quality')]
spellcheck *args:
    uv run --group lint codespell src tests packages docs README.md CLAUDE.md --skip="*.lock,*.svg,.git,__pycache__,.pytest_cache,tests/lean_spec/snappy/testdata" --ignore-words=.codespell-ignore-words.txt "$@"

[group('quality')]
mdformat *args:
    uv run --group docs mdformat --check docs/ "$@"

[group('tests')]
test *args:
    uv run --group test pytest tests -n auto --maxprocesses=10 --durations=10 --dist=worksteal "$@"

[group('tests')]
test-cov *args:
    uv run --group test pytest --cov --cov-report=html --cov-report=term "$@"

[group('tests')]
test-cov-gate *args:
    uv run --group test pytest --cov --cov-report=term-missing --cov-fail-under=80 "$@"

[group('tests')]
test-consensus *args:
    uv run --group test pytest -n auto --maxprocesses=10 --durations=10 --dist=worksteal tests/lean_spec/subspecs/containers tests/lean_spec/subspecs/forkchoice tests/lean_spec/subspecs/networking "$@"

[group('tests')]
fill *args:
    uv run --group test fill --fork=Devnet --clean -n auto "$@"

[group('tests')]
apitest server_url *args:
    uv run --group test apitest "{{server_url}}" "$@"

[group('tests')]
interop *args:
    uv run --group test pytest tests/interop/ -v --no-cov --timeout=120 -x --tb=short --log-cli-level=INFO "$@"

[group('docs')]
docs *args:
    uv run --group docs mkdocs build "$@"

[group('docs')]
docs-serve *args:
    uv run --group docs mkdocs serve "$@"
