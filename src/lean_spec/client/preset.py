"""
The `preset` module contains the parameters that are used to configure the
Lean Consensus chain.
"""

from remerkleable.basic import uint64

# Time parameters
# ---------------------------------------------------------------

# 4 seconds
SLOT_DURATION_MS = 4000

# Basis points (out of 10000)
PROPOSER_REORG_CUTOFF_BPS: 2500
VOTE_DUE_BPS: 5000
FAST_CONFIRM_DUE_BPS: 7500
VIEW_FREEZE_CUTOFF_BPS: 7500

# Misc
# ---------------------------------------------------------------

# 2^18, enough for 2^18 / (60 / 4) / 60 / 24 = 12.1 days
MAX_HISTORICAL_BLOCK_HASHES: uint64 = 262144

VALIDATOR_REGISTRY_LIMIT: uint64 = 4096
