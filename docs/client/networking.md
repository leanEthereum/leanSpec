# Networking

## Overview

Lean consensus validators communicate over a peer-to-peer network. This
document describes the network architecture and protocols.

## Network Stack

The network uses modern protocols:

QUIC provides the transport layer. QUIC combines the features of TCP with
better performance and built-in encryption. It runs over UDP.

TLS 1.3 secures connections. Every connection is encrypted and authenticated.

Node identities come from secp256k1 keys. Each validator has a key pair. The
public key serves as the node identity.

Multistream-select handles protocol negotiation. When nodes connect, they
agree on which protocols to use.

Gossipsub distributes messages. This is a publish-subscribe system optimized
for blockchain networks.

## Node Discovery

Nodes need to find each other. For devnet testing, nodes are configured
statically. A file lists all node addresses.

Each node entry contains an ENR. This is an Ethereum Node Record. It includes:

- The node's public key
- Network address
- Port numbers
- Other metadata

In production, dynamic discovery would replace static configuration.

## Message Propagation

Most network traffic uses gossipsub. Gossipsub is efficient for broadcasting
messages to many peers.

### How Gossipsub Works

Each node maintains connections to several peers. These form a mesh network.
When a node has a message, it sends to mesh peers. They forward to their mesh
peers. This continues until everyone receives the message.

Gossipsub has tunable parameters. These control mesh size, forward behavior,
and message caching. The parameters are set for blockchain workloads.

### Topic Structure

Messages are organized by topic. Topic names follow a pattern that includes:

- Network identifier
- Devnet number
- Message type
- Encoding format

This structure lets clients subscribe to relevant messages and ignore others.

### Message Types

Two main message types exist:

Blocks are proposed by validators. They propagate on the block topic. Every
node needs to see blocks quickly.

Attestations come from all validators. They propagate on the attestation topic. High volume
but small messages.

### Encoding

All messages use SSZ encoding followed by Snappy compression. SSZ provides
deterministic serialization. Snappy reduces bandwidth.

### Message Identity

Each message gets a unique identifier. The identifier comes from hashing
message content. This prevents duplicates and enables deduplication.

The hash includes a domain separator. This separates valid messages from
malformed ones.

## Direct Requests

Some operations need direct communication between specific peers. This uses
request-response protocols.

### Status Exchange

When nodes connect, they exchange status. Status includes:

- Current chain head
- Latest finalized block
- Other sync information

This tells peers if they're synchronized. If one peer is behind, it knows to
request blocks.

### Block Requests

Nodes can request specific blocks by hash. This is useful for sync and filling
gaps.

A node sends a list of block hashes. The peer responds with the blocks if it
has them.

This is more efficient than gossip for targeted queries.

## Connection Management

Nodes maintain multiple peer connections. Too few connections risks isolation.
Too many waste resources.

Gossipsub parameters control target connection counts. The mesh tries to
maintain a stable size.

Nodes disconnect from peers that misbehave. This includes sending invalid
messages or violating protocol rules.

## Security Considerations

All connections are encrypted. Eavesdroppers cannot read network traffic.

Messages are authenticated at the application layer. Validators sign their
attestations and blocks. This prevents impersonation.

The network must resist denial of service. Rate limiting and resource
management protect against overload.

Invalid messages are rejected and tracked. Persistent misbehavior leads to
disconnection.

## Testing Configuration

Devnet configurations are simpler than production. Static peer lists replace
discovery. Small networks enable easier debugging.

These simplifications are appropriate for testing. Production networks will
need more sophisticated peer management.

## Protocol Evolution

Network protocols will evolve across devnets. Early versions establish basic
functionality. Later versions add optimizations and features.

Protocol versioning allows gradual upgrades. Old and new versions can
coexist temporarily during transitions.
