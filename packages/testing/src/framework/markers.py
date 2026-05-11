"""Helper for the capability-requirement pytest marker."""

import pytest


def requires_capability(*capabilities: type) -> pytest.MarkDecorator:
    """Build a capability-requirement marker over one or more Protocols.

    Why a helper is needed at all:

    - Pytest treats a single class argument to a marker as the
      thing being decorated, not as marker data.
    - That makes pytest try to instantiate the class.
    - Protocols can't be instantiated, so applying the marker
      directly to a Protocol raises TypeError at import.

    What this helper does:

    - Passes the capability through as marker data instead of as
      the decoration target.
    - Validates each argument up front, so non-Protocol classes
      and Protocols missing the runtime-checkable decorator fail
      at import rather than at test collection.

    Raises:
        TypeError: If any argument is not a runtime-checkable Protocol.
    """
    for cap in capabilities:
        if not getattr(cap, "_is_runtime_protocol", False):
            raise TypeError(
                f"requires_capability expects @runtime_checkable Protocols; "
                f"got {getattr(cap, '__name__', cap)!r}"
            )
    return pytest.mark.requires.with_args(*capabilities)
