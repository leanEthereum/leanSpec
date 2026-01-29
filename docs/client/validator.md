# Validator Behavior

## Overview

Validators participate in consensus by proposing blocks and producing attestations.
Optionally validators can opt-in to behave as aggregators in their committee.
This document describes what honest validators do.

## Validator Assignment

For testing, validators are pre-assigned to clients. A configuration file maps
each client to specific validator indices.

This assignment spreads validators across different implementations. This
diversity helps test interoperability.

In production, validator assignment will work differently. The current approach
is temporary for devnet testing.

## Attestation Committees and Subnets

Attestation committee is a group of validators contributing to the common
aggregated attestations. Subnets are network channels dedicated to specific committees.

In the devnet-3 design, however, there is one global subnet for signed
attestations propagation, in addition to publishing into per committee subnets.
This is due to 3SF-mini consensus design, that requires 2/3+ of all
attestations to be observed by any validator to compute safe target correctly.

Note that non-aggregating validators do not need to subscribe to committee
attestation subnets. They only need to subscribe to the global attestation
subnet.

Every validator is assigned to a single committee. Number of committees is
defined in config.yaml. Each committee maps to a subnet ID. Validator's
subnet ID is derived using their validator index modulo number of committees.
This is to simplify debugging and testing. In the future, validator's subnet ID
will be assigned randomly per epoch.

## Aggregator assignment

Some validators are self-assigned as aggregators. Aggregators collect and combine
attestations from other validators in their committee. To become an aggregator,
a validator sets `is_aggregator` flag to true as ENR record field.

## Proposing Blocks

Each slot has exactly one designated proposer. The proposer is determined by
simple math: divide the slot number by total validators, the remainder is the
proposer's index.

This is deterministic. Everyone can compute who should propose at any slot.

### When to Propose

Proposers create blocks at the start of the slot. Specifically, in the first
interval of the slot's four intervals.

Early proposal gives other validators time to see and create an attestation on the block.

### Building a Block

The proposer queries fork choice for the current head. This is the parent for
the new block.

The proposer collects recent attestations. Valid attestations get included in the block.
An attestation is valid if its source matches the current justified checkpoint.

The proposer keeps adding attestations until no more valid attestations remain. This
maximizes block utility.

After building the block, the proposer computes the state root. This is the
state hash after applying the block.

### Broadcasting

The proposer signs the block and broadcasts it to the network. Other validators
receive and validate it.

## Attesting

Every validator attests in every slot. Attesting happens in the second interval,
after proposals are made.

### What to Attest For

Validators express their own views with an attestation, especially for three things:

- The chain head
- A target to justify
- An already justified source

The head is what fork choice says is canonical. The target is computed based on
safe blocks and justifiability rules. The source is the most recent justified
checkpoint.

### Why Attest

Attestations drive justification and finalization. When 2/3 of validators attestation for the
same target, it becomes justified. Justification eventually leads to
finalization.

Attestations also inform fork choice. Other validators see these attestations and use them to
compute the head.

### Broadcasting Attestations

Validators sign their attestations and broadcast them into the global
attestation topic and its corresponding subnet topic.

## Timing

The slot divides into four one-second intervals:

- Interval 0: Proposals happen
- Interval 1: Attestations happen
- Interval 2: Safe targets update
- Interval 3: More processing

This rhythm keeps the network synchronized. Validators know when to expect
blocks and attestations.

## Aggregation

Attestation aggregation combines multiple attestations into one. This saves bandwidth and
block space.

Devnet-3 introduces signatures aggregation. Aggregators will collect attestations and combine them. Aggregated attestations will be broadcast separately.

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
- Producing an attestation every slot
- Following fork choice
- Obeying timing rules

Correct implementation ensures the network functions properly.

## Testing Focus

The current design prioritizes testability over production features. Round
robin proposals are simple but insecure for production. Pre-assigned validators
are convenient but not decentralized.

These compromises are acceptable for testing. They let developers focus on core
consensus mechanics.
