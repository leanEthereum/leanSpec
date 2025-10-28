# Heavily inspired by Reth: https://github.com/paradigmxyz/reth/blob/4c39b98b621c53524c6533a9c7b52fc42c25abd6/Makefile
.DEFAULT_GOAL := help

##@ Installation
.PHONY: install
install: # Install dependencies.
	uv sync

##@ Development
.PHONY: lint
lint: # Run linting and automatically apply fixes.
	uv run ruff check --fix src tests
	uv run ruff format src tests
	uv run mypy src tests

.PHONY: test
test: # Run all tests.
	uv run pytest

.PHONY: test-client-specs
test-client-specs: # Run tests for the client specs only.
	uv run pytest \
		tests/lean_spec/subspecs/containers \
		tests/lean_spec/subspecs/forkchoice \
		tests/lean_spec/subspecs/networking \
		tests/lean_spec/subspecs/ssz

##@ Others
.PHONY: pr
pr: # Run checks for a PR.
	make lint && \
	make test

.PHONY: help
help: # Display this help.
	@awk 'BEGIN {FS = ":.*#"; printf "Usage:\n  make \033[34m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?#/ { printf "  \033[34m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
