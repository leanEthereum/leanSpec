# Lean Consensus Specification - Docker Image
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

# Copy the virtual environment from builder stage.
# This is safe because both stages use the same Python base image (python:3.12-slim),
# same architecture, and same paths. Avoids reinstalling dependencies in runtime stage.
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

# Copy the virtual environment from builder stage.
# This is safe because both stages use the same Python base image (python:3.12-slim),
# same architecture, and same paths. Avoids reinstalling dependencies in runtime stage.
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

# Create directory for genesis and validator keys
RUN mkdir -p /app/data

# Expose p2p port
EXPOSE 9000

# Set entrypoint to lean_spec directly
# Users can pass CLI arguments directly: docker run lean_spec --genesis /data/config.yaml --bootnode ...
ENTRYPOINT ["uv", "run", "python", "-m", "lean_spec"]

# Default arguments (can be overridden)
# Users must provide at least --genesis argument
CMD ["--help"]

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
