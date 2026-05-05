"""
Validator service constants.

Operational thresholds governing validator duty execution.
"""

from __future__ import annotations

from typing import Final

SYNC_LAG_THRESHOLD: Final[int] = 4
"""
Maximum tolerated lag, in slots, between wall-clock and the local head before
validator duties are skipped.

A node whose local head trails wall clock by more than this attests against a
stale subtree, depositing fork-choice weight on the wrong branch.

The gate also checks peer-reported head slots: if no peer claims a recent head,
the network as a whole is lagging (e.g. a streak of skipped proposals) and the
gate stays open so the chain can keep progressing.
"""
