# Lean Ethereum Specifications - Docker Image
# Multi-stage build for smaller final image

# =============================================================================
# Stage 1: Builder - Install dependencies and build
# =============================================================================
FROM python:3.12-slim AS builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    git \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust nightly (required for lean-multisig-py)
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly \
    && rustup default nightly

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set working directory
WORKDIR /app

# Copy dependency files first for better caching
COPY pyproject.toml uv.lock LICENSE README.md ./
COPY packages/ ./packages/

# Install dependencies (creates virtual environment in .venv)
RUN uv sync --frozen

# Copy the rest of the source code
COPY src/ ./src/
COPY tests/ ./tests/

# =============================================================================
# Stage 2: Runtime - Minimal image for running tests
# =============================================================================
FROM python:3.12-slim AS runtime

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install uv for running commands
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash leanspec
USER leanspec

WORKDIR /app

# Copy the virtual environment and source from builder
COPY --from=builder --chown=leanspec:leanspec /app/.venv /app/.venv
COPY --from=builder --chown=leanspec:leanspec /app/src /app/src
COPY --from=builder --chown=leanspec:leanspec /app/tests /app/tests
COPY --from=builder --chown=leanspec:leanspec /app/packages /app/packages
COPY --from=builder --chown=leanspec:leanspec /app/pyproject.toml /app/pyproject.toml
COPY --from=builder --chown=leanspec:leanspec /app/uv.lock /app/uv.lock
COPY --from=builder --chown=leanspec:leanspec /app/LICENSE /app/LICENSE
COPY --from=builder --chown=leanspec:leanspec /app/README.md /app/README.md

# Set environment to use the virtual environment
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Default command - run tests
CMD ["uv", "run", "pytest"]

# =============================================================================
# Stage 3: Node - Lean consensus node runner
# =============================================================================
FROM python:3.12-slim AS node

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install uv for running commands
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash leanspec
USER leanspec

WORKDIR /app

# Copy the virtual environment and source from builder
COPY --from=builder --chown=leanspec:leanspec /app/.venv /app/.venv
COPY --from=builder --chown=leanspec:leanspec /app/src /app/src
COPY --from=builder --chown=leanspec:leanspec /app/packages /app/packages
COPY --from=builder --chown=leanspec:leanspec /app/pyproject.toml /app/pyproject.toml
COPY --from=builder --chown=leanspec:leanspec /app/uv.lock /app/uv.lock
COPY --from=builder --chown=leanspec:leanspec /app/LICENSE /app/LICENSE
COPY --from=builder --chown=leanspec:leanspec /app/README.md /app/README.md

# Set environment to use the virtual environment
ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

# Consensus node configuration via environment variables
ENV GENESIS_FILE="" \
    BOOTNODE="" \
    LISTEN_ADDR="/ip4/0.0.0.0/tcp/9000" \
    CHECKPOINT_SYNC_URL="" \
    VALIDATOR_KEYS_PATH="" \
    NODE_ID="lean_spec_0" \
    VERBOSE=""

# Create directory for genesis and validator keys
RUN mkdir -p /app/data

# Expose p2p port
EXPOSE 9000

# Entrypoint script to handle CLI arguments
COPY --chown=leanspec:leanspec <<'EOF' /app/entrypoint.sh
#!/bin/bash
set -e

# Build lean_spec command with environment variables
CMD="uv run python -m lean_spec"

# Genesis file (required)
if [ -n "$GENESIS_FILE" ]; then
    CMD="$CMD --genesis $GENESIS_FILE"
else
    echo "Error: GENESIS_FILE environment variable is required"
    echo "Usage: docker run -e GENESIS_FILE=/app/data/genesis.json ..."
    exit 1
fi

# Bootnode (optional, can be multiple)
if [ -n "$BOOTNODE" ]; then
    # Split on commas and add each bootnode
    IFS=',' read -ra BOOTNODES <<< "$BOOTNODE"
    for bn in "${BOOTNODES[@]}"; do
        CMD="$CMD --bootnode $bn"
    done
fi

# Listen address
if [ -n "$LISTEN_ADDR" ]; then
    CMD="$CMD --listen $LISTEN_ADDR"
fi

# Checkpoint sync URL
if [ -n "$CHECKPOINT_SYNC_URL" ]; then
    CMD="$CMD --checkpoint-sync-url $CHECKPOINT_SYNC_URL"
fi

# Validator keys path
if [ -n "$VALIDATOR_KEYS_PATH" ]; then
    CMD="$CMD --validator-keys $VALIDATOR_KEYS_PATH"
fi

# Node ID
if [ -n "$NODE_ID" ]; then
    CMD="$CMD --node-id $NODE_ID"
fi

# Verbose logging
if [ "$VERBOSE" = "true" ] || [ "$VERBOSE" = "1" ]; then
    CMD="$CMD -v"
fi

# Execute the command
echo "Starting lean_spec node..."
echo "Command: $CMD"
exec $CMD
EOF

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]

# =============================================================================
# Stage 4: Development - Full environment with all tools
# =============================================================================
FROM builder AS development

# Copy all project files
COPY . .

# Re-sync to ensure all dev dependencies are installed
RUN uv sync --frozen

# Set environment
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Default command for development
CMD ["/bin/bash"]
