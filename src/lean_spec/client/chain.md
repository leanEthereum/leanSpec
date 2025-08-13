# Lean Consensus Experimental Chain

## Configuration

### Time parameters

| Name                                  | Value                     |     Unit     |   Duration    |
| ------------------------------------- | ------------------------- | :----------: | :-----------: |
| `SLOT_DURATION_MS`                    | `uint64(4000)`            | milliseconds | 4 seconds     |
| `PROPOSER_REORG_CUTOFF_BPS`           | `uint64(2500)`            |      bps     | 25% into slot |
| `VOTE_DUE_BPS`                        | `uint64(5000)`            |      bps     | 50% into slot |
| `FAST_CONFIRM_DUE_BPS`                | `uint64(7500)`            |      bps     | 75% into slot |
| `VIEW_FREEZE_CUTOFF_BPS`              | `uint64(7500)`            |      bps     | 75% into slot |

## Presets

### State list lengths

| Name                           | Value                                 |       Unit       |   Duration    |
| ------------------------------ | ------------------------------------- | :--------------: | :-----------: |
| `HISTORICAL_ROOTS_LIMIT`       | `uint64(2**18)` (= 262,144)           | historical roots |   12.1 days   |
| `VALIDATOR_REGISTRY_LIMIT`     | `uint64(2**12)` (= 4,096)             |    validators    |               |
