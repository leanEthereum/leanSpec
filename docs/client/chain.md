# Lean Consensus Experimental Chain
<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Configuration](#Configuration)
  - [Time parameters](#Time parameters)
- [Presets](#Presets)
- [STF](#STF)

<!-- mdformat-toc end -->

## Introduction

This document specs the behavior and functionality of the lean chain. This is a minimal chain spec to prepare the lean clients to be ready for post quantum signature devnets with the following features:

| Devnet | Purpose                    | ETA |
| ------ | -------                    | :-: |
| 0      | pq signature preparation   | Oct 2025 |


### Devnet 0 Functionality

1. Chain-ing
  This is beacon style chaining via latest_block_header in state verified against parent hash of the new block. LMD-Ghost (without application of beacon chain style filter block tree)
2. 3SF mini justification & finalization
  Departing from the beacon chain epoch centric processing, the lean chain employs a slightly translated version of the 3SF mini where all validators vote every slot.
3. No Aggregation
  The votes casted in the network are simply consumed and packed without aggregation. Beacon style aggregation will be introduced in the Devnet 2.

## Configuration

### Time parameters

| Name                                  | Value                     |     Unit     |   Duration    |
| ------------------------------------- | ------------------------- | :----------: | :-----------: |
| `SLOT_DURATION_MS`                    | `uint64(4000)`            | milliseconds | 4 seconds     |
| `INTERVALS_PER_SLOT`                  | `uint64(4)`               | intervals    | 1 second      |

## Presets

### State list lengths

| Name                           | Value                                 |       Unit       |   Duration    |
| ------------------------------ | ------------------------------------- | :--------------: | :-----------: |
| `HISTORICAL_ROOTS_LIMIT`       | `uint64(2**18)` (= 262,144)           | historical roots |   12.1 days   |
| `VALIDATOR_REGISTRY_LIMIT`     | `uint64(2**12)` (= 4,096)             |    validators    |               |
