# Validator Behavior

## Overview

Validators participate in consensus by proposing blocks and voting. This
document describes what honest validators do.

## Validator Assignment

For testing, validators are pre-assigned to clients. A configuration file maps
each client to specific validator indices.

This assignment spreads validators across different implementations. This
diversity helps test interoperability.

In production, validator assignment will work differently. The current approach
is temporary for devnet testing.

## Proposing Blocks

Each slot has exactly one designated proposer. The proposer is determined by
simple math: divide the slot number by total validators, the remainder is the
proposer's index.

This is deterministic. Everyone can compute who should propose at any slot.

### When to Propose

Proposers create blocks at the start of the slot. Specifically, in the first
interval of the slot's four intervals.

Early proposal gives other validators time to see and vote on the block.

### Building a Block

The proposer queries fork choice for the current head. This is the parent for
the new block.

The proposer collects recent votes. Valid votes get included in the block.
A vote is valid if its source matches the current justified checkpoint.

The proposer keeps adding votes until no more valid votes remain. This
maximizes block utility.

After building the block, the proposer computes the state root. This is the
state hash after applying the block.

### Broadcasting

The proposer signs the block and broadcasts it to the network. Other validators
receive and validate it.

## Voting

Every validator votes in every slot. Voting happens in the second interval,
after proposals are made.

### What to Vote For

Validators vote for three things:

- The chain head
- A target to justify
- An already justified source

The head is what fork choice says is canonical. The target is computed based on
safe blocks and justifiability rules. The source is the most recent justified
checkpoint.

### Why Vote

Votes drive justification and finalization. When 2/3 of validators vote for the
same target, it becomes justified. Justification eventually leads to
finalization.

Votes also inform fork choice. Other validators see these votes and use them to
compute the head.

### Broadcasting Votes

Validators sign their votes and broadcast them. The network uses a single topic
for all votes. No subnets or committees in the current design.

## Timing

The slot divides into four one-second intervals:

- Interval 0: Proposals happen
- Interval 1: Votes happen
- Interval 2: Safe targets update
- Interval 3: More processing

This rhythm keeps the network synchronized. Validators know when to expect
blocks and votes.

## Aggregation

Vote aggregation combines multiple votes into one. This saves bandwidth and
block space.

Devnet 0 has no aggregation. Each vote is separate. Future devnets will add
aggregation.

When aggregation is added, aggregators will collect votes and combine them.
Aggregated attestations will be broadcast separately.

## Signature Handling

In Devnet 0, signatures are not real. All signature fields contain zeros. This
lets clients test consensus logic without implementing post-quantum signatures
yet.

Devnet 1 will use real signatures. These signatures will be large, around 3-4
kilobytes. The signature scheme will be post-quantum secure.

## Client Responsibilities

Clients must implement the validator logic correctly. This includes:

- Tracking which validators they control
- Proposing when scheduled
- Voting every slot
- Following fork choice
- Obeying timing rules

Correct implementation ensures the network functions properly.

## Testing Focus

The current design prioritizes testability over production features. Round
robin proposals are simple but insecure for production. Pre-assigned validators
are convenient but not decentralized.

These compromises are acceptable for testing. They let developers focus on core
consensus mechanics.
