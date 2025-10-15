# Data Structures

## Overview

The lean chain uses several data structures to represent consensus information.
All data uses SSZ encoding for consistency and efficiency.

## Configuration

The chain needs basic configuration to start. This includes when genesis occurs
and how many validators participate. Configuration is simple and determined at
chain launch.

## Checkpoints

A checkpoint marks a specific moment in the chain. It combines a block
identifier with a slot number. Checkpoints are used for justification and
finalization.

Justified checkpoints indicate validator agreement. Finalized checkpoints
provide stronger guarantees.

## Chain State

The state contains everything needed for consensus. It tracks the current slot,
recent blocks, and validator votes. State also records which blocks are
justified and finalized.

Historical information is kept for a limited time. This prevents state from
growing unbounded.

Validator votes are stored in a space-efficient format. This reduces the size
of state while maintaining all necessary information.

## Blocks

A block proposes changes to the chain. It references its parent block, creating
a chain. The block includes a state root that represents the result of
applying this block.

Each block has a proposer who created it. The slot determines which validator
can propose.

## Block Headers

Block headers summarize blocks without storing full content. The header
includes references to the parent and the resulting state. It also contains a
hash of the block body.

Headers are smaller than full blocks. They're useful for tracking the chain
without storing everything.

## Block Contents

Block contents consist of operations. Currently, the main operation is voting.
Validators submit votes which are packaged into blocks.

Later versions will add more operation types.

## Signed Blocks

A signed block is a block with a cryptographic signature from the proposer.
The signature proves the proposer created this specific block.

In Devnet 0, signatures are placeholders. Real signatures will be added in
Devnet 1.

## Votes

Votes are how validators express their view of the chain. Each vote specifies:

- What the validator thinks is the chain head
- What should be justified
- What is already justified

Votes can be aggregated to save space, but Devnet 0 doesn't do this yet.

## Signed Votes

A signed vote is a vote with a validator signature. The signature proves which
validator submitted the vote.

Like block signatures, vote signatures are placeholders in Devnet 0.

## Aggregated Attestations

Multiple votes can be combined into a single attestation. This reduces network
bandwidth and block size.

Aggregation is not implemented in Devnet 0. It will be added in later devnets.

## Encoding

All structures use SSZ encoding. SSZ provides deterministic serialization and
efficient merkleization.

Hash functions used for merkleization differ by devnet. Early devnets use
SHA256. Later devnets will switch to Poseidon2 for better SNARK compatibility.

## Implementation

The Python specification defines exact structure layouts. This documentation
explains purpose and usage. For precise field definitions and types, see the
implementation code.
