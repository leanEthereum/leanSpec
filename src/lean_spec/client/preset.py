"""
The `preset` module contains the parameters that are used to configure the
Lean Consensus chain.
"""

from ethereum_types.numeric import U64

# Time parameters
# ---------------------------------------------------------------

# 4 seconds
SLOT_DURATION_MS: U64 = U64(4000)

# Basis points (out of 10000)
PROPOSER_REORG_CUTOFF_BPS: U64 = U64(2500)
VOTE_DUE_BPS: U64 = U64(5000)
FAST_CONFIRM_DUE_BPS: U64 = U64(7500)
VIEW_FREEZE_CUTOFF_BPS: U64 = U64(7500)

# Misc
# ---------------------------------------------------------------

# 2^18, enough for 2^18 / (60 / 4) / 60 / 24 = 12.1 days
MAX_HISTORICAL_BLOCK_HASHES: U64 = U64(262144)

VALIDATOR_REGISTRY_LIMIT: U64 = U64(4096)
