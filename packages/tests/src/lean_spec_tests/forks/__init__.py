"""Fork definitions for consensus layer testing."""

from typing import Type

from .base import BaseFork, BaseForkMeta
from .forks import Devnet, NewFork
from .helpers import (
    ALL_FORKS,
    get_fork_by_name,
    get_forks,
    get_forks_with_no_parents,
    get_from_until_fork_set,
)

Fork = Type[BaseFork]

__all__ = [
    "ALL_FORKS",
    "BaseFork",
    "BaseForkMeta",
    "Devnet",
    "Fork",
    "NewFork",
    "get_fork_by_name",
    "get_forks",
    "get_forks_with_no_parents",
    "get_from_until_fork_set",
]
