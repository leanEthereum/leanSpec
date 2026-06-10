"""Tests for the spec observer singleton and its context managers."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager

import pytest

from lean_spec.spec.observability import (
    observe_on_attestation,
    observe_on_block,
    observe_state_transition,
    observer as observer_module,
    set_observer,
)
from lean_spec.spec.observability.observer import _NullObserver


@pytest.fixture(autouse=True)
def _reset_observer() -> Iterator[None]:
    """Restore the default no-op observer between tests."""
    yield
    set_observer(_NullObserver())


# Each row pairs an observer hook with the context manager that publishes it.
SPEC_EVENTS = [
    pytest.param("state_transition_timed", observe_state_transition, id="state_transition"),
    pytest.param("on_block_timed", observe_on_block, id="on_block"),
    pytest.param("on_attestation_timed", observe_on_attestation, id="on_attestation"),
]


class TestNullObserverDefault:
    """The no-op observer is the registered singleton until set_observer is called."""

    def test_default_observer_is_null(self) -> None:
        """The process starts with the no-op observer registered."""
        assert isinstance(observer_module._observer, _NullObserver)

    @pytest.mark.parametrize(("method_name", "_cm"), SPEC_EVENTS)
    def test_null_observer_discards_events(
        self,
        method_name: str,
        _cm: Callable[[], AbstractContextManager[None]],
    ) -> None:
        """Every hook on the no-op observer accepts a sample and returns None."""
        assert getattr(_NullObserver(), method_name)(0.5) is None


class TestSetObserver:
    """set_observer replaces the module singleton."""

    def test_replaces_singleton(self) -> None:
        """Registering an observer makes it the module singleton."""
        observer = _RecordingObserver()
        set_observer(observer)
        assert observer_module._observer is observer


class _RecordingObserver:
    """Captures every hook call keyed by method name."""

    def __init__(self) -> None:
        self.samples: dict[str, list[float]] = {
            "state_transition_timed": [],
            "on_block_timed": [],
            "on_attestation_timed": [],
        }

    def state_transition_timed(self, seconds: float) -> None:
        self.samples["state_transition_timed"].append(seconds)

    def on_block_timed(self, seconds: float) -> None:
        self.samples["on_block_timed"].append(seconds)

    def on_attestation_timed(self, seconds: float) -> None:
        self.samples["on_attestation_timed"].append(seconds)


class TestObserveContextManagers:
    """Each observe_* context manager publishes on clean exit, not on raise."""

    @pytest.mark.parametrize(("method_name", "cm"), SPEC_EVENTS)
    def test_publishes_on_clean_exit(
        self,
        method_name: str,
        cm: Callable[[], AbstractContextManager[None]],
    ) -> None:
        """A clean exit publishes exactly one non-negative duration to the hook."""
        observer = _RecordingObserver()
        set_observer(observer)

        with cm():
            pass

        assert len(observer.samples[method_name]) == 1
        assert observer.samples[method_name][0] >= 0.0

    @pytest.mark.parametrize(("method_name", "cm"), SPEC_EVENTS)
    def test_does_not_publish_when_body_raises(
        self,
        method_name: str,
        cm: Callable[[], AbstractContextManager[None]],
    ) -> None:
        """A body that raises propagates the exception and publishes nothing."""
        observer = _RecordingObserver()
        set_observer(observer)

        with pytest.raises(RuntimeError), cm():
            raise RuntimeError("boom")

        assert observer.samples[method_name] == []
