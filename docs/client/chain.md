# Lean Consensus Chain

## Overview

The lean chain is a minimal consensus protocol designed for testing
post-quantum signatures. It removes complexity while keeping core consensus
mechanisms.

## Development Timeline

Two initial devnets are planned:

- **Devnet 0** (September 2025): Minimal consensus without real signatures
- **Devnet 1** (October 2025): Post-quantum signatures enabled

## Core Design

### Block Linking

Each block references its parent. The chain forms by following these parent
references backwards. If a parent reference is invalid, the block is rejected.

Fork choice determines which chain is canonical when multiple valid chains
exist.

### Consensus Without Epochs

Traditional beacon chain organizes time into epochs. Lean chain removes this.
All validators are expected to create, sign, and broadcast an attestation in every slot. This simplifies the protocol significantly.

### Signature Handling

Devnet 0 has no signature verification. All signature fields contain zero
bytes. This lets clients test consensus logic before post-quantum signatures
are ready.

Real signatures will be large, around 3-4 kilobytes each. Devnet 1 will test
these.

### Attestation Processing

Attestations are collected and included in blocks without aggregation. Each attestation is
separate. This is simpler than beacon chain aggregation.

Later devnets will add aggregation to reduce bandwidth.

### Block Proposals

Each slot has one designated proposer. The proposer is determined by simple
math: take the slot number and divide by total validators, the remainder tells
you which validator proposes.

This is deterministic and simple. No randomness needed.

### Validator Lifecycle

Validators are simple in Devnet 0. No deposits or withdrawals. No penalties or
slashing. Each validator has equal voting power.

Validators are assigned to clients through configuration files. This works for
testing but will change for production.

## Time Structure

Time divides into slots. Each slot lasts 4 seconds. Slots subdivide into 4
intervals of 1 second each.

Different actions happen in different intervals. This creates a predictable
rhythm for the network.

Historical data is kept for about 12 days. After that, old block references
are removed. The chain can support up to 4096 validators in current
configuration.

## Chain Justification

Blocks become justified when enough validators attestation for them. Justification
happens when 2/3 of validators agree.

Not every slot can be justified. Certain slots are special based on how far
they are from the last finalized slot. Recent slots are always valid. For
older slots, only specific positions can be justified. This prevents
justification from spreading too thin.

## Chain Finalization

Finalization provides stronger guarantees than justification. A block is
finalized when validators attestation for it and there are no other justifiable
positions between it and what they're voting for.

Finalized blocks cannot be reverted. This provides economic certainty.

## Genesis

The chain starts at genesis. Genesis is simple: a configuration file specifies
when to start and how many validators exist.

Clients generate genesis state locally. No special ceremony needed. The first
real block after genesis gets special treatment to bootstrap the consensus
process.

## State Transitions

Each block modifies the chain state. The state transition function is
deterministic. Given a state and a valid block, everyone computes the same new
state.

Invalid blocks are rejected. Invalid means:

- Arithmetic overflow or underflow
- Failed assertion
- State root mismatch

Empty slots still advance state. If no block appears in a slot, the state
still updates to reflect the missing slot.

## Block Validation

Blocks must pass several checks:

- Slot matches current state
- Block is newer than previous block
- Proposer is correct for this slot
- Parent reference is valid

After these checks, the block is processed. Attestation processing happens next.

## Attestation Validation

Each attestation must meet requirements:

- Source must be justified
- Target must not already be justified
- Block roots must be valid
- Slot relationships must make sense
- Target must be in a justifiable position

Invalid attestations are ignored. Valid attestations are counted. When enough attestations
accumulate, justification happens.

## Justification Tracking

The system tracks which blocks are being voted for and which validators have
voted. This data is stored in a flattened format for efficiency.

When justification occurs, the tracking data is cleaned up. Only active voting
attempts are kept.

## Implementation Notes

This documentation describes concepts and mechanisms. Implementation details
live in the Python specification code. The code contains precise logic and data
structures.

This documentation helps you understand what the system does and why. The code
shows exactly how.
