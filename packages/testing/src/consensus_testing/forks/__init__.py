"""Fork definitions for consensus layer testing."""

from consensus_testing.forks.base import BaseFork
from consensus_testing.forks.forks import Lstar

FORKS_BY_NAME: dict[str, type[BaseFork]] = {"lstar": Lstar}
"""Registered consensus forks, keyed by lowercase fork name."""

__all__ = [
    "BaseFork",
    "FORKS_BY_NAME",
    "Lstar",
]
