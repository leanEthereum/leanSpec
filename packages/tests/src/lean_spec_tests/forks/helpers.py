"""Fork helper functions and auto-discovery."""

from typing import FrozenSet, List, Set, Type

from . import forks
from .base import BaseFork


# Auto-discover all forks from the forks module
def _discover_forks() -> List[Type[BaseFork]]:
    """
    Discover all fork classes by scanning the forks module.

    Returns:
        List of all BaseFork subclasses found in the forks module.
    """
    discovered: List[Type[BaseFork]] = []
    for name in dir(forks):
        obj = getattr(forks, name)
        # Check if it's a type (class) and subclass of BaseFork (but not BaseFork itself)
        if isinstance(obj, type) and issubclass(obj, BaseFork) and obj is not BaseFork:
            discovered.append(obj)
    return discovered


# Discover all forks at module import time
_all_forks: List[Type[BaseFork]] = _discover_forks()

# Create frozen set excluding ignored forks
ALL_FORKS: FrozenSet[Type[BaseFork]] = frozenset(fork for fork in _all_forks if not fork.ignore())
"""All available consensus forks, excluding ignored forks."""


def get_forks() -> Set[Type[BaseFork]]:
    """
    Return the set of all available forks.

    Returns:
        Set of all non-ignored fork classes.
    """
    return set(ALL_FORKS)


def get_fork_by_name(fork_name: str) -> Type[BaseFork] | None:
    """
    Get a fork class by its name.

    Args:
        fork_name: Name of the fork (case-insensitive).

    Returns:
        The fork class, or None if not found.
    """
    for fork in get_forks():
        if fork.name().lower() == fork_name.lower():
            return fork
    return None


def get_forks_with_no_parents(forks: Set[Type[BaseFork]]) -> Set[Type[BaseFork]]:
    """
    Get all forks that have no parent forks in the given set.

    Args:
        forks: Set of forks to search.

    Returns:
        Set of forks with no parents (root forks).
    """
    result: Set[Type[BaseFork]] = set()
    for fork in forks:
        has_parent = False
        for other_fork in forks - {fork}:
            if other_fork < fork:  # other_fork is older than fork
                has_parent = True
                break
        if not has_parent:
            result.add(fork)
    return result


def get_from_until_fork_set(
    forks: Set[Type[BaseFork]],
    forks_from: Set[Type[BaseFork]],
    forks_until: Set[Type[BaseFork]],
) -> Set[Type[BaseFork]]:
    """
    Get all forks in the range from forks_from to forks_until (inclusive).

    Args:
        forks: The complete set of forks to filter.
        forks_from: Start of the range (inclusive).
        forks_until: End of the range (inclusive).

    Returns:
        Set of forks in the specified range.
    """
    result: Set[Type[BaseFork]] = set()
    for fork_from in forks_from:
        for fork_until in forks_until:
            for fork in forks:
                # Fork must be >= fork_from and <= fork_until
                if fork >= fork_from and fork <= fork_until:
                    result.add(fork)
    return result
