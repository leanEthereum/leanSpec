# Fork Choice

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Fork choice](#fork-choice)
  - [Configuration](#configuration)
  - [Helpers](#helpers)
    - [`get_fork_choice_head`](#get_fork_choice_head)
    - [`get_latest_justified`](#get_latest_justified)
    - [`Store`](#store)
    - [`get_forkchoice_store`](#get_forkchoice_store)
    - [`update_head`](#update_head)
    - [`update_safe_target`](#update_safe_target)
      - [`get_vote_target`](#get_vote_target)
    - [`accept_new_votes`](#accept_new_votes)
      - [`tick_interval`](#tick_interval)
    - [`get_proposal_head`](#get_proposal_head)
  - [Handlers](#handlers)
    - [`on_tick`](#on_tick)
    - [`on_attestation`](#on_attestation)
    - [`on_block`](#on_block)

<!-- mdformat-toc end -->

## Fork choice

At genesis, let `store = get_forkchoice_store(genesis_state, genesis_block)` and
update `store` by running:

- `on_tick(store, time)` whenever `time > store.time` where `time` is the
  current Unix time
- `on_block(store, block)` whenever a block `block: SignedBlock` is
  received
- `on_attestation(store, attestation, from_block)` whenever an attestation `attestation` is
  received, either in a block or on network
- `get_proposal_head(store, slot)` whenever validator intends to make block proposal

### Configuration

### Helpers

#### `get_fork_choice_head`

```python
# Use LMD GHOST to get the head, given a particular root (usually the latest
# known justified block)
#
# Note: 3sf mini divergence: it directly accepts latest_votes (known or new) as
# tracked in the store
def get_fork_choice_head(
    blocks: Dict[str, Block], root: str, latest_votes: List[Checkpoint], min_score: int = 0
) -> str:
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
                block_hash = blocks[block_hash].parent_root

    # Identify the children of each block
    children_map: Dict[str, List[str]] = {}
    for _hash, block in blocks.items():
        if block.parent_root and vote_weights.get(_hash, 0) >= min_score:
            children_map.setdefault(block.parent_root, []).append(_hash)

    # Start at the root (latest justified hash or genesis) and repeatedly
    # choose the child with the most latest votes, tiebreaking by slot then hash
    current = root
    while True:
        children = children_map.get(current, [])
        if not children:
            return current
        current = max(children, key=lambda x: (vote_weights.get(x, 0), blocks[x].slot, x))
```

#### `get_latest_justified`

```python
def get_latest_justified(states: Dict[str, State]) -> Optional[Checkpoint]:
    # Find the State object with the maximum s.latest_justified.slot value
    latest = max(states.values(), key=lambda s: s.latest_justified.slot)

    # Return the Checkpoint from that State object
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
class Store(object):
    # time in intervals since genesis
    time: Interval
    config: Config
    head: Root
    safe_target: Root
    latest_justified: Checkpoint
    latest_finalized: Checkpoint
    blocks: Dict[Root, Block] = field(default_factory=dict)
    states: Dict[Root, State] = field(default_factory=dict)
    latest_known_votes: Dict[ValidatorIndex, SignedValidatorAttestation] = field(default_factory=dict)
    latest_new_votes: Dict[ValidatorIndex, SignedValidatorAttestation] = field(default_factory=dict)
```

#### `get_forkchoice_store`

The provided anchor-state will be regarded as a trusted state, to not roll back
beyond. This should be the genesis state for a full client.

```python
def get_forkchoice_store(anchor_state: State, anchor_block: Block) -> Store:
    assert anchor_block.state_root == hash_tree_root(anchor_state)
    anchor_root = hash_tree_root(anchor_block)
    anchor_slot = anchor_block.slot

    return Store(
        time=anchor_slot * INTERVALS_PER_SLOT,
        config=anchor_state.config,
        head=anchor_root,
        safe_target=anchor_root,
        latest_justified=anchor_state.latest_justified,
        latest_finalized=anchor_state.latest_finalized,
        blocks={anchor_root: copy(anchor_block)},
        states={anchor_root: copy(anchor_state)},
    )
```

#### `update_head`

```python
def update_head(store: Store) -> None:
    """
    Updates the store's latest justified checkpoint, head, and latest finalized state.
    """
    store.latest_justified = get_latest_justified(store.states)
    store.head = get_fork_choice_head(
        store.blocks, store.latest_justified.root, store.latest_known_votes
    )

    store.latest_finalized = store.states[store.head].latest_finalized
```

#### `update_safe_target`

```python
# Compute the latest block that the validator is allowed to choose as the target
def update_safe_target(store: Store):
    # 2/3rd majority min voting voting weight for target selection
    min_target_score = -(-store.config.num_validators * 2 // 3)  # ceiling division

    store.safe_target = get_fork_choice_head(
        store.blocks,
        store.latest_justified.root,
        store.latest_new_votes,
        min_score=min_target_score,
    )
```

##### `get_vote_target`

```python
def get_vote_target(store: Store) -> Checkpoint:
    """
    Calculates the target checkpoint for a vote based on the head, safe target,
    and latest finalized state.
    """
    # Start from head as target candidate
    target_block_root = store.head

    # If there is no very recent safe target, then vote for the k'th ancestor
    # of the head
    for i in range(3):
        if store.blocks[target_block_root].slot > store.blocks[store.safe_target].slot:
            target_block_root = store.blocks[target_block_root].parent_root

    # If the latest finalized slot is very far back, then only some slots are
    # valid to justify, make sure the target is one of those
    while not is_justifiable_slot(
        store.latest_finalized.slot, store.blocks[target_block_root].slot
    ):
        target_block_root = store.blocks[target_block_root].parent_root

    target_block = store.blocks[target_block_root]
    return Checkpoint(root=hash_tree_root(target_block), slot=target_block.slot)
```

#### `accept_new_votes`

```python
# Process new votes that the staker has received. Vote processing is done
# at a particular time, because of safe target and view merge rules
def accept_new_votes(store: Store):
    """
    Accepts the latest new votes, merges them into the known votes,
    and then updates the fork-choice head.
    """
    for validator_id in store.latest_new_votes.keys():
        store.latest_known_votes[validator_id] = store.latest_new_votes[validator_id]

    store.latest_new_votes = {}
    update_head(store)
```

##### `tick_interval`

```python
def tick_interval(store: Store, has_proposal: bool) -> None:
    store.time += 1
    current_interval = store.time % INTERVALS_PER_SLOT
    if current_interval == 0:
        if has_proposal:
            accept_new_votes(store)
    elif current_interval == 1:
        # validators will vote in this interval using safe target previously
        # computed
        pass
    elif current_interval == 2:
        update_safe_target(store)
    else:
        accept_new_votes(store)
```

#### `get_proposal_head`

```python
def get_proposal_head(store: Store, slot: Slot) -> Root:
    slot_time = store.config.genesis_time + slot * SECONDS_PER_SLOT
    # this would be a no-op if the store is already ticked to the current time
    on_tick(store, slot_time, True)
    # this would be a no-op or just a fast compute if store was already ticked to
    # accept new votes for a registered validator with the node
    accept_new_votes(store)
    return store.head
```

### Handlers

#### `on_tick`

```python
# called every interval and with has_proposal flag on the new slot interval if
# node has a validator with proposal in this slot so as to not delay accepting
# new votes and parallelize compute
def on_tick(store: Store, time: int, has_proposal: bool) -> None:
    """
    Ticks the store forward in intervals until it reaches the given time.

    :param store: The Store object to be updated.
    :param time: The current time in seconds.
    :param has_proposal: A boolean indicating if there is a proposal in this tick.
    """
    # Calculate the number of intervals that have passed since genesis
    tick_interval_time = (time - store.genesis_time) // SECONDS_PER_INTERVAL

    # Tick the store one interval at a time until the target time is reached
    while store.time < tick_interval_time:
        # Determine if a proposal should be signaled for the next interval
        should_signal_proposal = has_proposal and (store.time + 1) == tick_interval_time

        # Tick the interval and potentially signal a proposal
        tick_interval(store, should_signal_proposal)
```

#### `on_attestation`

```python
def on_attestation(store: Store, vote: SignedValidatorAttestation, is_from_block: bool = False) -> None:
    """
    Validates and processes a new attestation (a signed vote), updating the store's
    latest votes.
    """
    validate_on_attestation(store, vote)

    validator_id = vote.validator_id

    if is_from_block:
        # update latest known votes if this is latest
        latest_vote = store.latest_known_votes.get(validator_id)
        if latest_vote is None or latest_vote.message.slot < vote.message.slot:
            store.latest_known_votes[validator_id] = vote

        # clear from new votes if this is latest
        latest_vote = store.latest_new_votes.get(validator_id)
        if latest_vote is not None and latest_vote.message.slot < vote.message.slot:
            del store.latest_new_votes[validator_id]
    else:
        # forkchoice should be correctly ticked to current time before
        # importing gossiped attestations
        time_slots = store.time // SECONDS_PER_INTERVAL
        assert vote.message.slot <= time_slots

        # update latest new votes if this is the latest
        latest_vote = store.latest_new_votes.get(validator_id)
        if latest_vote is None or latest_vote.message.slot < vote.message.slot:
            store.latest_new_votes[validator_id] = vote
```

#### `on_block`

```python
def on_block(store: Store, signed_block: SignedBlock) -> None:
    """
    Processes a new block, updates the store, and triggers a head update.
    """
    block = signed_block.message
    signatures = signed_block.signature
    block_hash = compute_hash(block)
    # If the block is already known, ignore it
    if block_hash in store.blocks:
        return

    parent_state = store.states.get(block.parent_root)
    # at this point parent state should be available so node should
    # sync parent chain if not available before adding block to forkchoice
    assert parent_state is not None, "Parent state not found, sync parent chain first"

    valid_signatures = validate_signatures(block.signature)
    # Get post state from STF (State Transition Function)
    state = state_transition(copy.deepcopy(parent_state), block, valid_signatures, True)
    store.blocks[block_hash] = block
    store.states[block_hash] = state

    # add block votes to the onchain known last votes
    for i in [0..block.body.attestations.len]:
        validator_attestation = block.body.attestations[i]
        signed_attestation = SignedValidatorAttestation(
            message=validator_attestation,
            # eventually one would be able to associate and consume an aggregated signature
            # for individual vote validity with that information encoded in the signature
            signature=signatures[i]
        )

        # Add block votes to the onchain known last votes
        on_attestation(store, validator_attestation, True)
    # also add the proposer vote to onchain known last votes
    proposer_attestation=SignedValidatorAttestation(
        message=block.body.proposer_attestation,
        # currently proposer signature is only its vote signature till we can consume
        # aggregated signature type for purposes of validating and further packing the
        # signed vote in future blocks if required
        signature=signatures[signatures.len-1]
    )
    on_attestation(store, proposer_attestation)

    update_head(store)
```
