# Containers

## `Config`

```python
class Config(Container):
    // temporary property to support simplified round robin block production in absence of randao & deposit mechanisms
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
    justifications_validators: Bitlist[
        HISTORICAL_ROOTS_LIMIT * VALIDATOR_REGISTRY_LIMIT
    ]
```

## `Block`

```python
class Block(Container):
    slot: uint64
    proposer_index: uin64
    parent_root: Bytes32
    state_root: Bytes32
    body: BlockBody
```

## `BlockHeader`

```python
class BlockHeader(Container):
    slot: uint64
    proposer_index: uin64
    parent_root: Bytes32
    state_root: Bytes32
    body_root: Bytes32
```

## `BlockBody`


```python
class BlockBody(Container):
    votes: List[Vote, VALIDATOR_REGISTRY_LIMIT]
```

Remark: `votes` will be replaced by aggregated attestations.

## `SignedBlock`

```python
class SignedBlock(Container):
    message: Block,
    signature: Bytes32,
```

## `Vote`

```python
class Vote(Container):
    validator_id: uint64
    slot: uint64
    head: Checkpoint
    target: Checkpoint
    source: Checkpoint
```

## `SignedVote`

```python
class SignedVote(Container):
    data: Vote,
    signature: Bytes32,
```

## Remarks

- The signature type is still to be determined so `Bytes32` is used in the
  interim. The actual signature size is expected to be a lot larger (~3 KiB).
