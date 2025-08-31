

## Introduction

## Fork choice

At genesis, let `store = get_forkchoice_store(genesis_state, genesis_block)` and
update `store` by running:

- `on_tick(store, time)` whenever `time > store.time` where `time` is the
  current Unix time
- `on_block(store, block)` whenever a block `block: SignedBeaconBlock` is
  received
- `on_attestation(store, attestation)` whenever an attestation `attestation` is
  received

### Configuration

### Helpers

#### `get_fork_choice_head`

```python
# Use LMD GHOST to get the head, given a particular root (usually the latest 
# known justified block)
#
# Note: 3sf mini divergence: it directly accepts latest_votes (known or new) as 
# tracked in the store
def get_fork_choice_head(blocks: Dict[str, Block],
                         root: str,
                         latest_votes: List[Checkpoint],
                         min_score: int = 0) -> str:
    # Start at genesis by default
    if root == ZERO_HASH:
        root = min(blocks.keys(), key=lambda block: blocks[block].slot)

    # For each block, count the number of votes for that block. A vote
    # for any descendant of a block also counts as a vote for that block
    vote_weights: Dict[str, int] = {}

    for vote in latest_votes.values():
        if vote.root in blocks:
            block_hash = vote.root
            while blocks[block_hash].slot > blocks[root].slot:
                vote_weights[block_hash] = vote_weights.get(block_hash, 0) + 1
                block_hash = blocks[block_hash].parent

    # Identify the children of each block
    children_map: Dict[str, List[str]] = {}
    for _hash, block in blocks.items():
        if block.parent and vote_weights.get(_hash, 0) >= min_score:
            children_map.setdefault(block.parent, []).append(_hash)

    # Start at the root (latest justified hash or genesis) and repeatedly
    # choose the child with the most latest votes, tiebreaking by slot then hash
    current = root
    while True:
        children = children_map.get(current, [])
        if not children:
            return current
        current = max(children,
                      key=lambda x: (vote_weights.get(x, 0), blocks[x].slot, x))
```

#### `get_latest_justified`

```python
def get_latest_justified(states: Dict[str, State]) -> Checkpoint:
    latest = max(
        states.values(),
        key=lambda s: s.latest_justified.slot
    )
    return latest.latest_justified
```


#### `Store`

The `Store` is responsible for tracking information required for the fork choice
algorithm. The important fields being tracked are described below:

- `latest_justified`: the highest-slot known justified block
- `latest_finalized`: the highest-slot known finalized block
- `latest_known_votes`: the latest by validator votes already applied
- `latest_new_votes`: the latest by validator new votes not yet applied

```python
@dataclass
class Store(object):
    time: uint64
    config: Config
    head: Root,
    safe_target: Root,
    latest_justified: Checkpoint
    latest_finalized: Checkpoint
    blocks: Dict[Root, Block] = field(default_factory=dict)
    states: Dict[Root, State] = field(default_factory=dict)
    latest_known_head_votes: Dict[ValidatorIndex, Checkpoint] = field(default_factory=dict)
    latest_new_head_votes: Dict[ValidatorIndex, Checkpoint] = field(default_factory=dict)
```

#### `get_forkchoice_store`

The provided anchor-state will be regarded as a trusted state, to not roll back
beyond. This should be the genesis state for a full client.

```python
def get_forkchoice_store(anchor_state: BeaconState, anchor_block: BeaconBlock) -> Store:
    assert anchor_block.state_root == hash_tree_root(anchor_state)
    anchor_root = hash_tree_root(anchor_block)
    anchor_slot = anchor_block.slot

    return Store(
        time=uint64(anchor_state.config.genesis_time + SECONDS_PER_SLOT * anchor_slot),
        config=anchor_state.config,
        head=anchor_root,
        safe_target=anchor_root,
        latest_justified=state.latest_justified,
        latest_finalized=state.latest_finalized,
        blocks={anchor_root: copy(anchor_block)},
        states={anchor_root: copy(anchor_state)},
    )
```


#### `update_head`

```python
def update_head(store: Store) -> Root:
    store.latest_justified = get_latest_justified(store.states)
    store.head = get_fork_choice_head(store.blocks, store.latest_justified.root, store.latest_known_votes)
    store.latest_finalized = store.states[store.head].latest_finalized
```

#### `update_safe_target`

```python
# Compute the latest block that the staker is allowed to choose
# as the target
    def update_safe_target(store: Store):
        store.safe_target = get_fork_choice_head(
            store.blocks,
            store.latest_justified.root,
            store.latest_new_votes,
            min_score=store.config.num_validators * 2 // 3
        )
```

##### `get_vote_target`
```python
def get_vote_target(store: Store, head_root: Root, slot: Slot) -> Checkpoint:
    target_block_root = store.head

    # If there is no very recent safe target, then vote for the k'th ancestor
    # of the head
    for i in range(3):
        if store.blocks[target_block_root].slot > store.blocks[self.safe_target].slot:
            target_block_root = store.blocks[target_block_root].parent

    # If the latest finalized slot is very far back, then only some slots are
    # valid to justify, make sure the target is one of those
    while not is_justifiable_slot(store.latest_finalized.slot, store.blocks[target_block_root].slot):
        target_block_root = store.blocks[target_block_root].parent

    return Checkpoint(
        root=target_block_root,
        slot=store.blocks[target_block_root].root
    )
```

