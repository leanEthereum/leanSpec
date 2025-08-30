# Lean Consensus Experimental Chain
<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Configuration](#Configuration)
  - [Time parameters](#Time parameters)
- [Presets](#Presets)
- [Genesis](#genesis)
  - [Genesis state](#genesis-state)
  - [Genesis block](#genesis-block)
- [STF](#STF)

<!-- mdformat-toc end -->

## Introduction

This document specs the behavior and functionality of the lean chain. This is a minimal chain spec to prepare the lean clients to be ready for post quantum signature devnets with the following features:

| Devnet | Purpose                    | ETA |
| ------ | -------                    | :-: |
| 0      | minimal consensus          | Sep 2025 |
| 1      | pq signature               | Oct 2025 |


### Devnet 0 Functionality

1. Chain-ing
  This is beacon style chaining via latest_block_header in state verified against parent hash of the new block. LMD-Ghost (without application of beacon chain style filter block tree)
2. 3SF mini justification & finalization
  Departing from the beacon chain epoch centric processing, the lean chain employs a slightly translated version of the 3SF mini where all validators vote every slot.
3. Empty signatures
  Since we will be moving to post quantum signatures `Devnet1` onwards, `Devnet0` data is generated with zero bytes signatures with no signature verification involved. This means voting is a trusted process where the client creates a vote as per their assigned validators.
4. No Aggregation
  The votes casted in the network are simply consumed and packed without aggregation. Beacon style aggregation will be introduced in the Devnet 2.
5. Round robin proposals
  The proposal assignment process has also been kept simple to just assign the proposals based on a round robin process based on the validator index. This makes proposal also a trusted process where the client proposes a block as per their assigned validators.
5. Simplified Validators
  There is no validator deposit, activation, withdrawal or slashing making the validator lifecyle super simple. Each validator has the weight of `1` and since validators don't even generate signatures, there is no validator tracking in the state. Validators are assigned to the clients based on a config file.

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

## Helper functions

_Note:_ The definitions below are for specification purposes and are not necessarily optimal implementations.

### State accessors

#### `get_justifications`

Returns a map of `root -> justifications` constructed from the flattened data in
the state:

 - `state.justifications_roots` which is a list of block roots that are under
   voting consideration
 - `state.justifications_validators` which are flattened list of validator ids
   which have voted for the respective roots

A client implementation may cache this map on the first construction for performance.

```python
def get_justifications(state: State) -> Dict[str, List[bool]]:
    justifications = {}

    for i, root in enumerate(state.justifications_roots):
        # Calculate the relevant index range in the flattened bitlist for the current root
        start_idx = i * VALIDATOR_REGISTRY_LIMIT
        end_idx = start_idx + VALIDATOR_REGISTRY_LIMIT

        # Get the slice of the bitlist for this root
        validator_votes = state.justifications_validators[start_idx:end_idx]

        # Convert bitlist to list of booleans
        votes_list = [bool(validator_votes[j]) for j in range(len(validator_votes))]

        # Store in the justifications map
        justifications[root] = votes_list

    return justifications
```

#### `set_justifications`

Saves a map of `root -> justifications` back into the state's flattened data structure.

```python
def set_justifications(state: State, justifications: Dict[str, List[bool]]) -> None:
    justifications_roots = List[Bytes32, HISTORICAL_ROOTS_LIMIT]
    flattened_justifications = []

    for root, votes in justifications.items():
        # Assert that votes list has exactly VALIDATOR_REGISTRY_LIMIT items.
        # If the length is incorrect, the constructed bitlist will be corrupt.
        assert len(votes) == VALIDATOR_REGISTRY_LIMIT

        justifications_roots.append(root)
        flattened_justifications.extend(votes)

    # Create a new Bitlist with all the flattened votes
    justifications_validators = Bitlist[HISTORICAL_ROOTS_LIMIT * VALIDATOR_REGISTRY_LIMIT](*flattened_justifications)

    state.justifications_roots = justifications_roots
    state.justifications_validators = justifications_validators
```

### Misc

#### `is_justifiable_slot`

```python
def is_justifiable_slot(finalized_slot: int, candidate: int):
    assert candidate >= finalized_slot
    delta = candidate - finalized_slot
    return (
        delta <= 5
        or (delta ** 0.5) % 1 == 0            # any x^2
        or ((delta + 0.25) ** 0.5) % 1 == 0.5 # any x^2+x
    )
```

## Genesis

The genesis for lean devnets especially `Devnet0` is rather simple. This can even be generated by clients locally:
Let `genesis_state = generate_genesis_state(genesis_time, num_validators)`
where:
 - `genesis_time` is the configured time for the genesis slot
 - `num_validators` is the configured number of validators to run the chain with

 Even though `Devnet0` has no individual validators tracking, there would also be no need for `genesis_validators_root` going further as well because the state and hence state root would already encode the genesis validator's array.

### Genesis state

```python
def generate_genesis_state(genesis_time: uint64, num_validators: uint64) -> State {
  state = State(
    config=Config(
      genesis_time=genesis_time,
      num_validators=num_validators,
    ),
    latest_block_header=BlockHeader(body_root=hash_tree_root(BlockBody())),
  )

  return state;
}
```

### Genesis block

Let `genesis_block = Block(state_root=hash_tree_root(genesis_state))`.

## STF

The state transition function follows on the lines of beacon chain STF except that there is no epoch processing. Furthermore to keep the STF prover friendly, all signatures in the block whether its signed block signature or signed votes signatures, will be verified outside the STF with a boolean flag `valid_signatures` to STF indicating the successful verification (or not) of all signatures in the block.

The post-state corresponding to a pre-state `state` and a signed block
`signed_block` is defined as `state_transition(state, signed_block)`. State
transitions that trigger an unhandled exception (e.g. a failed `assert` or an
out-of-range list access) are considered invalid. State transitions that cause a
`uint64` overflow or underflow are also considered invalid.

```python
def state_transition(
    state: State, signed_block: SignedBlock, valid_signatures: bool, validate_result: bool = True
) -> None:
    # Verify signatures
    assert valid_signatures == True

    block = signed_block.message
    # Process slots (including those with no blocks) since block
    process_slots(state, block.slot)
    # Process block
    process_block(state, block)
    # Verify state root
    if validate_result:
        assert block.state_root == hash_tree_root(state)
```

```python
def process_slots(state: State, slot: Slot) -> None:
    assert state.slot < slot
    while state.slot < slot:
        process_slot(state)
        state.slot = Slot(state.slot + 1)
```

```python
def process_slot(state: BeaconState) -> None:
    # Cache latest block header state root
    if state.latest_block_header.state_root == Bytes32():
        previous_state_root = hash_tree_root(state)
        state.latest_block_header.state_root = previous_state_root
```

### Block processing

```python
def process_block(state: State, block: Block) -> None:
    process_block_header(state, block)
    process_operations(state, block.body)
```

#### Block header

```python
def process_block_header(state: State, block: Block) -> None:
    # Verify that the slots match
    assert block.slot == state.slot
    # Verify that the block is newer than latest block header
    assert block.slot > state.latest_block_header.slot
    # Verify that proposer index is the correct index
    assert block.proposer_index == block.slot % state.config.num_validators
    # Verify that the parent matches
    assert block.parent_root == hash_tree_root(state.latest_block_header)

    # If this was first block post genesis, 3sf mini special treatment is required
    # to correctly set genesis block root as already justified and finalized. 
    # This is not possible at the time of genesis state generation and are set at 
    # zero bytes because genesis block is calculated using genesis state causing a 
    # circular dependancy
    if(state.latest_block_header.slot == 0)
        # block.parent_root is the genesis root
        state.latest_justified.root = block.parent_root
        state.latest_finalized.root = block.parent_root

    # now that we can vote on parent, push it at its correct slot index in the structures
    state.historical_block_hashes.push(block.parent_root)
    # genesis block is always justified
    state.justified_slots.push( state.latest_block_header.slot == 0 ? True : False)

    # if there were empty slots, push zero hash for those ancestors
    num_empty_slots = block.slot - state.latest_block_header.slot -1;
    while num_empty_slots > 0):
      state.historical_block_hashes.push(ZERO_HASH)
      state.justified_slots.push(False)
      num_empty_slots -= 1;

    # Cache current block as the new latest block
    state.latest_block_header = BeaconBlockHeader(
        slot=block.slot,
        proposer_index=block.proposer_index,
        parent_root=block.parent_root,
        state_root=Bytes32(),  # Overwritten in the next process_slot call
        body_root=hash_tree_root(block.body),
    )
```

#### Operations

```python
def process_operations(state: State, body: BlockBody) -> None:
    # process attestations/votes
    process_attestations(state, body.votes)
    # other operations will get added as the functionality evolves
```

```python
def process_attestations(state: State, votes: Vote[]) -> None:
    # get justifications, justified slots and historical block hashes are already upto
    # date as per the processing in process_block_header
    justifications = get_justifications(state)

    # From 3sf-mini/consensus.py - apply votes
    for vote in votes:
        # Ignore votes whose source is not already justified,
        # or whose target is not in the history, or whose target is not a
        # valid justifiable slot
        if (
            state.justified_slots[vote.source.slot] is False
            # This condition is missing in 3sf mini but has been added here because
            # we don't want to re-introduce the target again for remaining votes if
            # the slot is already justified and its tracking already cleared out 
            # from justifications map
            or state.justified_slots[vote.target.slot] is True
            or vote.source.root != state.historical_block_hashes[vote.source.slot]
            or vote.target.root != state.historical_block_hashes[vote.target.slot]
            or vote.target.slot <= vote.source.slot
            or not is_justifiable_slot(state.latest_finalized_slot, vote.target_slot)
        ):
            continue

        # Track attempts to justify new hashes
        if vote.target.root not in justifications:
            justifications[vote.target.root] = [False] * state.config.num_validators

        if not justifications[vote.target.root][vote.validator_id]:
            justifications[vote.target.root][vote.validator_id] = True

        count = sum(justifications[vote.target.root])

        # If 2/3 voted for the same new valid hash to justify
        # in 3sf mini this is strict equality, but we have updated it to >=
        # also have modified it from count >= (2 * state.config.num_validators) // 3
        # to prevent integer division which could lead to less than 2/3 of validators
        # justifying specially if the num_validators is low in testing scenarios
        if 3 * count >= (2 * state.config.num_validators):
            state.latest_justified = vote.target
            state.justified_slots[vote.target.slot] = True
            del justifications[vote.target.root]

            # Finalization: if the target is the next valid justifiable
            # hash after the source
            if not any(
                is_justifiable_slot(state.latest_finalized.slot, slot)
                for slot in range(vote.source.slot + 1, vote.target.slot)
            ):
                state.latest_finalized = vote.source

    # flatten and set updated justifications back to the state
    set_justifications(state, justifications)
```
