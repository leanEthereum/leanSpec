"""Registry of registered forks, ordered oldest to newest."""

from .protocol import ForkProtocol


class ForkRegistry:
    """Registry of registered forks, ordered by version."""

    def __init__(self, forks: list[ForkProtocol]) -> None:
        """
        Initialize with an ordered list of forks.

        Forks must be:

        - Strictly monotonic in VERSION (ascending).
        - Unique by NAME.

        Args:
            forks: Ordered list of fork implementations.

        Raises:
            ValueError: If the fork list is empty, versions are not strictly
                monotonic, or names collide.
        """
        if not forks:
            raise ValueError("ForkRegistry requires at least one fork")

        versions = [f.VERSION for f in forks]
        if any(versions[i] >= versions[i + 1] for i in range(len(versions) - 1)):
            raise ValueError(f"Forks must be ordered by strictly increasing VERSION: {versions}")

        names = [f.NAME for f in forks]
        if len(set(names)) != len(names):
            raise ValueError(f"Fork names must be unique: {names}")

        self._forks = forks
        self._by_name = {f.NAME: f for f in forks}

    @property
    def current(self) -> ForkProtocol:
        """Return the latest (highest version) fork."""
        return self._forks[-1]

    def get_fork(self, name: str) -> ForkProtocol:
        """
        Look up a fork by name.

        Args:
            name: Fork name (e.g. 'lstar').

        Returns:
            The matching ForkProtocol instance.

        Raises:
            KeyError: If no fork matches the name.
        """
        try:
            return self._by_name[name]
        except KeyError as exc:
            known = sorted(self._by_name)
            raise KeyError(f"Unknown fork: {name!r}. Known: {known}") from exc
