<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Validator identification](#validator-identification)
- [Block proposer selection](#block-proposer-selection)
  - [Construction & Broadcast](#construction--broadcast)
- [Attesting](#attesting)
  - [Validator Voting](#validator-voting)
    - [Construction & Broadcast](#construction--broadcast-1)
  - [Attestation Aggregation](#attestation-aggregation)
- [Remarks](#remarks)

<!-- mdformat-toc end -->

# Validator

## Validator identification

To ensure a good distribution of block proposer duties in a round-robin manner
and avoid clashing IDs, validator IDs are pre-assigned to each client
implementation in a yaml file at
[`src/lean_spec/client/validators.yaml`](../../src/lean_spec/client/validators.yaml).
For example:

```yaml
ream: [0, 3, 6, 9, 12, 15, 18, 21, 24, 27]
zeam: [1, 4, 7, 10, 13, 16, 19, 22, 25, 28]
quadrivium: [2, 5, 8, 11, 14, 17, 20, 23, 26, 29]
```

## Block proposer selection

A validator is expected to create, sign, and broadcast a block at the start of first interval(=0) of its proposal slot.

The block proposer shall be determined by the modulo of the current slot number
by the total number of validators, such that block proposers are determined in
a round-robin manner by the validator IDs.

```py
def is_proposer(state: BeaconState, validator_index: ValidatorIndex) -> bool:
    return get_current_slot() % state.config.num_validators == validator_index
```

#### Construction & Broadcast

The validator constructs, signs a `Block` message and further broadcasts the `SignedBlock` to the `block` p2p topic.

```python
def produce_block(store: Store, slot: Slot) -> Block:
  head_root = get_proposal_head(store)
  head_state = store.states[head_root]

  new_block, state = None, None
  votes_to_add = []

  # Keep attempt to add valid votes from the list of available votes
  while 1:
      new_block = Block(
          slot=new_slot,
          parent=store.head,
          votes=votes_to_add
      )
      state = process_block(head_state, new_block)
      new_votes_to_add = [
          vote for vote in store.latest_known_votes if
          vote.source == state.latest_justified and
          vote not in votes_to_add
      ]

      if len(new_votes_to_add) == 0:
          break
      votes_to_add.extend(new_votes_to_add)

  new_block.state_root = compute_hash(state)
  new_hash = compute_hash(new_block)

  store.blocks[new_hash] = new_block
  store.states[new_hash] = state

  return new_block
```

## Attesting

The attestation process consists of validator casting their votes and their subsequent aggregation.

### Validator Voting

A validator is expected to create, sign, and broadcast a `SignedVote` at the start of second interval(=1) of each slot.

#### Construction & Broadcast

The validator constructs, signs a `Vote` message and further broadcasts the `SignedVote` to the `attestation` p2p topic.

```python
def produce_attestation_vote(store: Store, slot: Slot) -> Vote:
    """
    Constructs a Vote object for an attestation based on the store's state.

    :param store: The Store object containing the fork choice state.
    :param slot: The slot for which the attestation is being made.
    :return: A fully constructed Vote object.
    """
    head = get_proposal_head(store, slot)
    target = get_vote_target(store)


    return Vote(
        slot=slot,
        head=head,
        target=target,
        source=store.latest_justified,
    )
```

Note that there are no separate subnets/committees for the attestations as of `devnet0`.

### Attestation Aggregation

At the start of third interval(=2) of each slot, aggregators will aggregate signed votes received into `Attestation`s and broadcast the same to be included in the next proposal.

However there is no aggregation in `devnet0` and the signed votes are directly included in the next proposal. Details for aggregation will be added in the future devnets.

## Remarks

- This spec is still missing the file format for the centralized, pre-generated
  OTS keys (if any)
