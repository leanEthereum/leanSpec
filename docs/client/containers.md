# Containers

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Encoding](#encoding)
- [`Config`](#config)
- [`Checkpoint`](#checkpoint)
- [`State`](#state)
- [`Block`](#block)
- [`BlockHeader`](#blockheader)
- [`BlockBody`](#blockbody)
- [`SignedBlock`](#signedblock)
- [`Vote`](#vote)
- [`SignedVote`](#signedvote)
  - [`Attestation`](#attestation)
- [Remarks](#remarks)

<!-- mdformat-toc end -->

## Encoding

The containers for various blockchain consensus objects are primarily SSZ objects. To be more prover friendly, the Poseidon2 hasher will be used for hash tree rooting of these objects. However `devnet0` & `devnet1` continue to use the sha256 hasher.

## `Config`

```python
class Config(Container):
    # temporary property to support simplified round robin block production in absence of randao & deposit mechanisms
    num_validators: uint64
    genesis_time: uint64
```

## `Checkpoint`

```python
class Checkpoint(Container):
    root: Bytes32
    slot: uint64
```

## `State`

```python
class State(Container):
    config: Config
    slot: uint64
    latest_block_header: BlockHeader

    latest_justified: Checkpoint
    latest_finalized: Checkpoint

    historical_block_hashes: List[Bytes32, HISTORICAL_ROOTS_LIMIT]
    justified_slots: List[bool, HISTORICAL_ROOTS_LIMIT]

    # Diverged from 3SF-mini.py:
    # Flattened `justifications: Dict[str, List[bool]]` for SSZ compatibility
    justifications_roots: List[Bytes32, HISTORICAL_ROOTS_LIMIT]
    justifications_validators: Bitlist[HISTORICAL_ROOTS_LIMIT * VALIDATOR_REGISTRY_LIMIT]
```

## `Block`

```python
class Block(Container):
    slot: uint64
    proposer_index: uint64
    parent_root: Bytes32
    state_root: Bytes32
    body: BlockBody
```

## `BlockHeader`

```python
class BlockHeader(Container):
    slot: uint64
    proposer_index: uint64
    parent_root: Bytes32
    state_root: Bytes32
    body_root: Bytes32
```

## `BlockBody`

```python
class BlockBody(Container):
    attestations: List[SignedVote, VALIDATOR_REGISTRY_LIMIT]
```

Remark: `SignedVote` will be replaced by aggregated attestations.

## `SignedBlock`

```python
class SignedBlock(Container):
    message: Block
    signature: Vector[byte, 4000]
```

## `Vote`

Vote is the attestation data that can be aggregated. Although note there is no aggregation yet in `devnet0`.

```python
class Vote(Container):
    slot: uint64
    head: Checkpoint
    target: Checkpoint
    source: Checkpoint
```

## `SignedVote`

```python
class SignedVote(Container):
    validator_id: uint64
    message: Vote
    # signature over vote message only as it would be aggregated later in attestation
    signature: Vector[byte, 4000]
```

#### `Attestation`

The votes are aggregated in `Attestation` similar to beacon protocol but without complication of committees. This is currently not used in `devnet0`.

```python
class Attestation(Container):
    aggregation_bits: Bitlist[VALIDATOR_REGISTRY_LIMIT]
    message: Vote
    # this is an aggregated zk proof and is not a fix size signature
    signature: List[byte, 4000]
```

## Remarks

- The signature type is still to be determined so `Bytes32` is used in the
  interim. The actual signature size is expected to be a lot larger (~3 KiB).
