"""Helpers for framework pytest markers.

The `@requires` marker registered in `pytest_plugins/filler.py` takes a
capability Protocol as its argument. Writing it as
`@pytest.mark.requires(SigScheme)` triggers pytest's auto-detection
heuristic that treats a single class argument as the decoration target,
which fails for Protocol classes ("Protocols cannot be instantiated").

The `requires(...)` helper here bypasses the heuristic by going through
`with_args`.

Preferred placement
-------------------
Match the existing fork-marker convention: pin at the module level
unless individual tests in the file need different capabilities.

Module-level (preferred when the whole file shares one capability set):

    from framework import requires
    from lean_spec.forks import SigScheme

    pytestmark = [pytest.mark.valid_until("Lstar"), requires(SigScheme)]

Per-function (only when tests within a module differ):

    @requires(SigScheme)
    def test_something(...): ...

Stack multiple `requires(...)` to AND-compose capabilities. Either form
works.
"""

import pytest


def requires(*capabilities: type) -> pytest.MarkDecorator:
    """Build a `@requires(...)` marker around one or more capabilities."""
    return pytest.mark.requires.with_args(*capabilities)
