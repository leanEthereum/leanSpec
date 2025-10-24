"""Consensus layer fork discovery and helpers."""

from typing import FrozenSet, Set, Type

from framework.forks import BaseFork
from framework.forks.helpers import (
    get_all_forks,
    get_forks_with_no_parents,
    get_from_until_fork_set,
)
from framework.forks.helpers import (
    get_fork_by_name as _get_fork_by_name,
)
from framework.forks.helpers import (
    get_forks as _get_forks,
)

from . import forks

# Discover all consensus forks at module import time
ALL_FORKS: FrozenSet[Type[BaseFork]] = get_all_forks(forks)
"""All available consensus forks, excluding ignored forks."""


def get_forks() -> Set[Type[BaseFork]]:
    """
    Return the set of all available consensus forks.

    Returns:
        Set of all non-ignored consensus fork classes.
    """
    return _get_forks(ALL_FORKS)


def get_fork_by_name(fork_name: str) -> Type[BaseFork] | None:
    """
    Get a consensus fork class by its name.

    Args:
        fork_name: Name of the fork (case-insensitive).

    Returns:
        The fork class, or None if not found.
    """
    return _get_fork_by_name(ALL_FORKS, fork_name)


# Re-export the generic helpers for convenience
__all__ = [
    "ALL_FORKS",
    "get_forks",
    "get_fork_by_name",
    "get_forks_with_no_parents",
    "get_from_until_fork_set",
]
