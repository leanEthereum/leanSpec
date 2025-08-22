# Lean Consensus Experimental Chain

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
