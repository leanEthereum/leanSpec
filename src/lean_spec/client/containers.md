# Containers

## `Config`

```python
class Config(Container):
    num_validators: uint64
```

## `Checkpoint`

```python
class Checkpoint(Container)
    root: Bytes32
    slot: uint64
```

## `State`

```python
class State(Container):
    config: Config

    latest_justified: Checkpoint
    latest_finalized: Checkpoint

    historical_block_hashes: List[Bytes32, MAX_HISTORICAL_BLOCK_HASHES]
    justified_slots: List[bool, MAX_HISTORICAL_BLOCK_HASHES]

    # Diverged from 3SF-mini.py:
    # Flattened `justifications: Dict[str, List[bool]]` for SSZ compatibility
    justifications_roots: List[Bytes32, MAX_HISTORICAL_BLOCK_HASHES]
    justifications_validators: Bitlist[
        MAX_HISTORICAL_BLOCK_HASHES * VALIDATOR_REGISTRY_LIMIT
    ]
```

## `Block`

```python
class Block(Container):
    slot: uint64
    parent: Bytes32
    votes: List[Vote, VALIDATOR_REGISTRY_LIMIT]
    state_root: Bytes32
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
