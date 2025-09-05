<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Validator identification](#validator-identification)
- [Block proposer selection](#block-proposer-selection)
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

The block proposer shall be determined by the modulo of the current slot number
by the total number of validators, such that block proposers are determined in
a round-robin manner by the validator IDs.

```py
def is_proposer(state: BeaconState, validator_index: ValidatorIndex) -> bool:
    return get_current_slot() % state.config.num_validators == validator_index
```

## Remarks

- This spec is still missing the file format for the centralized, pre-generated
  OTS keys (if any)
