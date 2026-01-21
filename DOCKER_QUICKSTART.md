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

All examples pass CLI arguments directly to the node. Simply append arguments after the image name.

### 1. Basic Passive Node

Run a node that syncs but doesn't validate:

```bash
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -p 9000:9000 \
  lean-spec:node \
  --genesis /app/data/config.yaml
```

### 2. Node with Bootnode

Connect to an existing network:

```bash
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -p 9001:9001 \
  lean-spec:node \
  --genesis /app/data/config.yaml \
  --bootnode /ip4/127.0.0.1/tcp/9000 \
  --listen /ip4/0.0.0.0/tcp/9001
```

### 3. Multiple Bootnodes

Connect to multiple peers:

```bash
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -p 9000:9000 \
  lean-spec:node \
  --genesis /app/data/config.yaml \
  --bootnode /ip4/192.168.1.10/tcp/9000 \
  --bootnode /ip4/192.168.1.11/tcp/9000 \
  --bootnode enr:-IS4QHCYrYZbAKW...
```

### 4. Validator Node

Run as a validator with keys:

```bash
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -v /path/to/keys:/app/keys:ro \
  -p 9010:9010 \
  lean-spec:node \
  --genesis /app/data/config.yaml \
  --validator-keys /app/keys \
  --node-id lean_spec_0 \
  --bootnode /ip4/127.0.0.1/tcp/9000 \
  --listen /ip4/0.0.0.0/tcp/9010
```

### 5. Checkpoint Sync

Fast sync from a finalized checkpoint:

```bash
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -v /path/to/keys:/app/keys:ro \
  -p 9020:9020 \
  --add-host=host.docker.internal:host-gateway \
  lean-spec:node \
  --genesis /app/data/config.yaml \
  --checkpoint-sync-url http://host.docker.internal:5052 \
  --validator-keys /app/keys \
  --node-id lean_spec_0 \
  --listen /ip4/0.0.0.0/tcp/9020
```

### 6. With Verbose Logging

Enable debug logs:

```bash
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -p 9000:9000 \
  lean-spec:node \
  --genesis /app/data/config.yaml \
  -v
```

### 7. Background Service

Run as a background service:

```bash
docker run -d \
  --name lean-spec-node \
  --restart unless-stopped \
  -v /path/to/genesis:/app/data:ro \
  -p 9000:9000 \
  lean-spec:node \
  --genesis /app/data/config.yaml \
  --bootnode /ip4/127.0.0.1/tcp/9000

# Check logs
docker logs -f lean-spec-node

# Stop
docker stop lean-spec-node
```

## Using with lean-quickstart Genesis

If you have the lean-quickstart repo with generated genesis:

```bash
# For local-devnet
docker run --rm \
  -v /path/to/lean-quickstart/local-devnet/genesis:/app/data:ro \
  -p 9000:9000 \
  lean-spec:node \
  --genesis /app/data/config.yaml \
  --validator-keys /app/data \
  --node-id lean_spec_0

# For ansible-devnet
docker run --rm \
  -v /path/to/lean-quickstart/ansible-devnet/genesis:/app/data:ro \
  -p 9000:9000 \
  lean-spec:node \
  --genesis /app/data/config.yaml \
  --validator-keys /app/data \
  --node-id lean_spec_0
```

## Command-Line Arguments Reference

| Argument | Description | Required |
|----------|-------------|----------|
| `--genesis PATH` | Path to genesis YAML file (config.yaml) | **Yes** |
| `--bootnode ADDR` | Bootnode multiaddr or ENR (can be specified multiple times) | No |
| `--listen ADDR` | Multiaddr to listen on (default: `/ip4/0.0.0.0/tcp/9000`) | No |
| `--checkpoint-sync-url URL` | URL for checkpoint sync (e.g., `http://host:5052`) | No |
| `--validator-keys PATH` | Path to validator keys directory | No |
| `--node-id ID` | Node identifier for validator assignment (default: `lean_spec_0`) | No |
| `-v, --verbose` | Enable debug logging | No |

Run `docker run lean-spec:node --help` to see all available options.

## Troubleshooting

### Error: "License file does not exist"

You may need to rebuild the image. The Dockerfile now includes LICENSE and README.md.

### Can't connect to bootnode

- Check that the bootnode is reachable from the container
- Use `host.docker.internal` to access services on the host machine
- Add `--add-host=host.docker.internal:host-gateway` if needed

### Port already in use

Change the port mapping: `-p 9001:9000` (host:container)

Or change the listen address: `--listen /ip4/0.0.0.0/tcp/9001`
