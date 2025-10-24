"""Generic fork helper functions for any Ethereum layer."""

from types import ModuleType
from typing import FrozenSet, List, Set, Type

from framework.forks import BaseFork


def discover_forks(forks_module: ModuleType) -> List[Type[BaseFork]]:
    """
    Discover all fork classes by scanning a forks module.

    Args:
        forks_module: The module containing fork definitions (e.g., consensus_testing.forks.forks).

    Returns:
        List of all BaseFork subclasses found in the module.
    """
    discovered: List[Type[BaseFork]] = []
    for name in dir(forks_module):
        obj = getattr(forks_module, name)
        # Check if it's a type (class) and subclass of BaseFork (but not BaseFork itself)
        if isinstance(obj, type) and issubclass(obj, BaseFork) and obj is not BaseFork:
            discovered.append(obj)
    return discovered


def get_all_forks(forks_module: ModuleType) -> FrozenSet[Type[BaseFork]]:
    """
    Get all available forks from a forks module, excluding ignored forks.

    Args:
        forks_module: The module containing fork definitions.

    Returns:
        Frozen set of all non-ignored fork classes.
    """
    all_forks = discover_forks(forks_module)
    return frozenset(fork for fork in all_forks if not fork.ignore())


def get_forks(all_forks: FrozenSet[Type[BaseFork]]) -> Set[Type[BaseFork]]:
    """
    Convert a frozen set of forks to a regular set.

    Args:
        all_forks: Frozen set of fork classes.

    Returns:
        Set of fork classes.
    """
    return set(all_forks)


def get_fork_by_name(all_forks: FrozenSet[Type[BaseFork]], fork_name: str) -> Type[BaseFork] | None:
    """
    Get a fork class by its name.

    Args:
        all_forks: Set of available forks to search.
        fork_name: Name of the fork (case-insensitive).

    Returns:
        The fork class, or None if not found.
    """
    for fork in all_forks:
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
