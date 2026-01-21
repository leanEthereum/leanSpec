# Docker Quick Start Guide

This guide shows how to run lean_spec as a consensus node using Docker.

## Prerequisites

- Docker installed
- Genesis file in the proper format (see below)

## Building the Images

```bash
# Build test image (for running pytest)
docker build -t lean-spec:test .

# Build node image (for running consensus node)
docker build --target node -t lean-spec:node .

# Build dev image (for development)
docker build --target development -t lean-spec:dev .
```

## Genesis File Format

The node expects a YAML genesis file (`config.yaml`) with this format:

```yaml
GENESIS_TIME: 1766620797
GENESIS_VALIDATORS:
  - "0xb4b1bd5c9e770811cfc54951ee396e0b423dd06a3d889a427cd28653d7f8a55eb161047b926bef60c6ed7231e38e9432e00e6547"
  - "0x10f8dd53e8ebbf36b4fc2b16bb9f5a30bf2aee6c3874c836a2060e32ed49f06704aa4b2a5cc86c533fb7d06fa1e73b69d9d98710"
  # ... more validators
```

## Running Examples

### 1. Basic Passive Node

Run a node that syncs but doesn't validate:

```bash
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -e GENESIS_FILE=/app/data/config.yaml \
  -p 9000:9000 \
  lean-spec:node
```

### 2. Node with Bootnode

Connect to an existing network:

```bash
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -e GENESIS_FILE=/app/data/config.yaml \
  -e BOOTNODE=/ip4/127.0.0.1/tcp/9000 \
  -p 9001:9001 \
  -e LISTEN_ADDR=/ip4/0.0.0.0/tcp/9001 \
  lean-spec:node
```

### 3. Validator Node

Run as a validator with keys:

```bash
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -e GENESIS_FILE=/app/data/config.yaml \
  -e VALIDATOR_KEYS_PATH=/app/data \
  -e NODE_ID=lean_spec_0 \
  -e BOOTNODE=/ip4/127.0.0.1/tcp/9000 \
  -p 9010:9010 \
  -e LISTEN_ADDR=/ip4/0.0.0.0/tcp/9010 \
  lean-spec:node
```

### 4. Checkpoint Sync

Fast sync from a finalized checkpoint:

```bash
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -e GENESIS_FILE=/app/data/config.yaml \
  -e CHECKPOINT_SYNC_URL=http://host.docker.internal:5052 \
  -e VALIDATOR_KEYS_PATH=/app/data \
  -e NODE_ID=zeam_0 \
  -p 9020:9020 \
  --add-host=host.docker.internal:host-gateway \
  lean-spec:node
```

### 5. With Verbose Logging

Enable debug logs:

```bash
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -e GENESIS_FILE=/app/data/config.yaml \
  -e VERBOSE=true \
  -p 9000:9000 \
  lean-spec:node
```

## Using with lean-quickstart Genesis

If you have the lean-quickstart repo with generated genesis:

```bash
# For local-devnet
docker run --rm \
  -v /path/to/lean-quickstart/local-devnet/genesis:/app/data:ro \
  -e GENESIS_FILE=/app/data/config.yaml \
  -e VALIDATOR_KEYS_PATH=/app/data \
  -e NODE_ID=zeam_0 \
  -p 9000:9000 \
  lean-spec:node

# For ansible-devnet
docker run --rm \
  -v /path/to/lean-quickstart/ansible-devnet/genesis:/app/data:ro \
  -e GENESIS_FILE=/app/data/config.yaml \
  -e VALIDATOR_KEYS_PATH=/app/data \
  -e NODE_ID=zeam_0 \
  -p 9000:9000 \
  lean-spec:node
```

## Environment Variables Reference

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `GENESIS_FILE` | Path to genesis YAML file (config.yaml) | - | **Yes** |
| `BOOTNODE` | Bootnode address(es), comma-separated | - | No |
| `LISTEN_ADDR` | Address to listen on | `/ip4/0.0.0.0/tcp/9000` | No |
| `CHECKPOINT_SYNC_URL` | URL for checkpoint sync | - | No |
| `VALIDATOR_KEYS_PATH` | Path to validator keys directory | - | No |
| `NODE_ID` | Node identifier for validator assignment | `lean_spec_0` | No |
| `VERBOSE` | Enable debug logging (`true`/`false`) | `false` | No |

## Troubleshooting

### Error: "GENESIS_FILE environment variable is required"

Make sure you're setting the `-e GENESIS_FILE=...` environment variable.

### Error: "License file does not exist"

You may need to rebuild the image. The Dockerfile now includes LICENSE and README.md.

### Can't connect to bootnode

- Check that the bootnode is reachable from the container
- Use `host.docker.internal` to access services on the host machine
- Add `--add-host=host.docker.internal:host-gateway` if needed

### Port already in use

Change the port mapping: `-p 9001:9000` (host:container)

Or change the listen address: `-e LISTEN_ADDR=/ip4/0.0.0.0/tcp/9001`
