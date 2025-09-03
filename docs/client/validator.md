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

The block proposer shall be determined by the modulo of the current slot number
by the total number of validators, such that block proposers are determined in
a round-robin manner by the validator IDs.

```py
def is_proposer(state: BeaconState, validator_index: ValidatorIndex) -> bool:
    return get_current_slot() % state.config.num_validators == validator_index
```

#### Construction proposal message

def 

## Attesting

A validator is expected to create, sign, and broadcast an attestation at the start of second interval(=1) of each slot.

#### Construct attestation message

```python
  def get_attestation_message(validator_id: ValidatorIndex, slot: Slot, store: Store)
  Vote(
      validator_id=validator_id,
      slot=slot,
      head=store.head,
      target=get_vote_target(store),
      source=store.latest_justified,
  )
```

##### Aggregate signature

No signature aggregation is to done in `devnet0`.

#### Broadcast attestation

Finally, the validator broadcasts `SignedVote` to the associated attestation
subnet, the `attestation` topic. There are no separate subnets for the attestations as of `devnet0`.


## Remarks

- This spec is still missing the file format for the centralized, pre-generated
  OTS keys (if any)
