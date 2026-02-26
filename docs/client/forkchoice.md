# Fork Choice

## Overview

When multiple valid chains exist, the protocol must choose one as canonical.
This is the fork choice problem. Lean chain solves it using LMD-GHOST with
modifications for the simpler protocol design.

## The Need for Fork Choice

Networks are not perfectly synchronized. Different validators may see different
blocks first. This creates temporary forks.

Fork choice provides a consistent rule. Every honest validator following the
rule will agree on the canonical chain. This agreement must exist for
consensus.

## How It Works

The fork choice algorithm starts from the most recently justified block. It
then follows validator attestations forward through the tree of blocks.

At each branch point, the algorithm picks the child with the most attestations. Attestation
for descendants count toward ancestors. This means voting for a block implicitly
supports its entire history.

The algorithm continues until reaching a leaf. That leaf becomes the chain head.

## Justification and Fork Choice

Only justified blocks can serve as fork choice starting points. This ties fork
choice to finalization.

Validators must justify new blocks before fork choice considers them. This
creates a feedback loop: attestations justify blocks, justified blocks anchor fork
choice, fork choice determines what to build on.

## Attestation Timing

Attestations aren't processed immediately. The protocol divides each slot into
intervals. Different intervals have different roles:

- Some intervals accept new attestations
- Some intervals update what's safe to attestation for
- Some intervals are for proposal

This careful timing prevents certain attacks and ensures validators have
consistent views.

## Safe Targets

Validators need to know where they can safely submit an attestation. The safe target mechanism
finds the latest block that has enough support.

A block needs attestations from 2/3 of validators to be safe. This threshold ensures
that conflicting blocks can't both be safe simultaneously.

## Computing Attestation Targets

When a validator creates an attestation, it must choose a target carefully. The target should be
recent but not too recent. It should be safe but not too old.

The algorithm starts from the current head and works backward. It moves back a
few blocks if needed. It continues until finding a position that can be
justified according to protocol rules.

## Handling New Information

Fork choice must handle new blocks and new attestations. When a block arrives, it gets
added to the tree. Its attestations are extracted and counted.

When an attestation arrives over gossip, it's held temporarily. Attestations are only counted
at specific times to maintain consistency.

## Genesis Initialization

Fork choice starts at genesis. The genesis block is automatically justified and
finalized. This bootstraps the entire process.

From genesis, each new block references its parent. The tree grows slot by
slot.

## Reorganizations

Sometimes fork choice changes. A new attestation might tip the balance to a different
fork. The head switches to the new fork.

Reorganizations are normal in the protocol. Shallow reorgs happen occasionally.
Deep reorgs past finalization cannot happen if 2/3 of validators are honest.

## View Consistency

Different validators may have different views temporarily. They might see
blocks in different orders. They might receive attestations at different times.

Fork choice rules ensure these differences don't break consensus. Eventually,
all honest validators converge on the same head.

## Finalization Interaction

Fork choice respects finalization. The starting point for fork choice is always
on the finalized chain. This prevents fork choice from reverting finalized
blocks.

As new blocks get finalized, the fork choice tree gets pruned. Old forks that
lost are discarded.

## Implementation Details

The specification code implements these concepts precisely. It maintains the
tree of blocks, tracks attestations, and computes the head.

This documentation explains the concepts. The code provides the exact algorithm.
