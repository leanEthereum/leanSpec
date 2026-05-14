"""Unit tests for fork capabilities and the requirement-marker dispatch."""

from typing import Any, ClassVar, Protocol, runtime_checkable

import pytest
from framework.forks import BaseFork
from framework.markers import requires_capability
from framework.pytest_plugins.filler import _check_markers_valid_for_fork

from lean_spec.forks import LstarSpec, SigScheme
from lean_spec.forks.protocol import ForkProtocol, SpecBlockType, SpecStateType
from lean_spec.subspecs.xmss.interface import TARGET_SIGNATURE_SCHEME
from lean_spec.types import ValidatorIndex


class _NoSigSpec(ForkProtocol):
    """Synthetic fork without the signature-scheme capability."""

    NAME: ClassVar[str] = "no_sig"
    VERSION: ClassVar[int] = LstarSpec.VERSION + 1
    GOSSIP_DIGEST: ClassVar[str] = "deadbeef"
    previous: ClassVar[type[ForkProtocol] | None] = LstarSpec

    def upgrade_state(self, state: SpecStateType) -> SpecStateType:
        """Identity migration."""
        return state

    def generate_genesis(self, genesis_time: Any, validators: Any) -> SpecStateType:
        """Not exercised."""
        raise NotImplementedError

    def create_store(
        self,
        state: SpecStateType,
        anchor_block: SpecBlockType,
        validator_id: ValidatorIndex | None,
    ) -> Any:
        """Not exercised."""
        raise NotImplementedError


class _NoSigFork(BaseFork):
    """Fork wrapper around the no-capability synthetic spec."""

    @classmethod
    def name(cls) -> str:
        return "_NoSigFork"

    @classmethod
    def spec_class(cls) -> type[_NoSigSpec]:
        return _NoSigSpec


class _LstarLikeFork(BaseFork):
    """Fork wrapper around the real Lstar spec, kept local to avoid pulling
    the consensus filler bootstrap into the unit-test import graph."""

    @classmethod
    def name(cls) -> str:
        return "_LstarLikeFork"

    @classmethod
    def spec_class(cls) -> type[LstarSpec]:
        return LstarSpec


def _fork_by_name_table(*forks: type[BaseFork]) -> Any:
    """Build a name lookup over the given forks."""
    table = {fork.name(): fork for fork in forks}
    return table.get


def _mark(name: str, *args: Any) -> Any:
    """Build a real pytest Mark via the public MarkDecorator path."""
    return getattr(pytest.mark, name)(*args).mark


class TestSigSchemeCapability:
    """A fork advertises the signature-scheme capability by binding the attribute."""

    def test_lstar_advertises_sigscheme(self) -> None:
        """The real fork passes the structural check."""
        assert isinstance(LstarSpec(), SigScheme)

    def test_lstar_sig_scheme_is_target_scheme(self) -> None:
        """The bound scheme is the same singleton resolved at import time."""
        assert LstarSpec.sig_scheme is TARGET_SIGNATURE_SCHEME

    def test_fork_without_attribute_not_recognized(self) -> None:
        """A fork lacking the attribute is structurally rejected."""
        assert not isinstance(_NoSigSpec(), SigScheme)


class TestRequiresCapabilityHelper:
    """The helper rejects non-runtime-checkable arguments at call time."""

    def test_accepts_runtime_checkable_protocol(self) -> None:
        """A runtime-checkable Protocol produces a usable marker."""
        decorator = requires_capability(SigScheme)
        assert decorator.mark.name == "requires"
        assert decorator.mark.args == (SigScheme,)

    def test_accepts_multiple_capabilities(self) -> None:
        """Capabilities round-trip into marker args in the order given."""

        @runtime_checkable
        class _Other(Protocol):
            other_attr: ClassVar[object]

        decorator = requires_capability(SigScheme, _Other)
        assert decorator.mark.args == (SigScheme, _Other)

    def test_rejects_non_runtime_checkable_protocol(self) -> None:
        """A plain Protocol is rejected at call time."""

        class _NotRuntimeCheckable(Protocol):
            sig_scheme: ClassVar[object]

        with pytest.raises(TypeError, match="runtime_checkable"):
            requires_capability(_NotRuntimeCheckable)

    def test_rejects_plain_class(self) -> None:
        """A non-Protocol class is rejected too."""

        class _PlainClass:
            sig_scheme: ClassVar[object] = object()

        with pytest.raises(TypeError, match="runtime_checkable"):
            requires_capability(_PlainClass)


class TestMarkerDispatch:
    """The capability marker AND-composes with the fork-range markers."""

    def test_no_markers_passes(self) -> None:
        """An unmarked test runs on any fork."""
        assert _check_markers_valid_for_fork([], _LstarLikeFork, _fork_by_name_table())

    def test_capability_present_passes(self) -> None:
        """Capability advertised → test included."""
        markers = [requires_capability(SigScheme).mark]
        assert _check_markers_valid_for_fork(markers, _LstarLikeFork, _fork_by_name_table())

    def test_capability_absent_fails(self) -> None:
        """Capability missing → test deselected."""
        markers = [requires_capability(SigScheme).mark]
        assert not _check_markers_valid_for_fork(markers, _NoSigFork, _fork_by_name_table())

    def test_composes_with_valid_until_and_passes(self) -> None:
        """Fork-range and capability both satisfied → test included."""
        markers = [
            _mark("valid_until", _LstarLikeFork.name()),
            requires_capability(SigScheme).mark,
        ]
        assert _check_markers_valid_for_fork(
            markers, _LstarLikeFork, _fork_by_name_table(_LstarLikeFork)
        )

    def test_composes_with_valid_until_and_fails_on_capability(self) -> None:
        """Fork-range passes but capability missing → deselected."""
        markers = [
            _mark("valid_until", _NoSigFork.name()),
            requires_capability(SigScheme).mark,
        ]
        assert not _check_markers_valid_for_fork(
            markers, _NoSigFork, _fork_by_name_table(_NoSigFork)
        )

    def test_valid_at_short_circuit_still_checks_capability(self) -> None:
        """Exact-fork match still requires the capability."""
        markers = [
            _mark("valid_at", _NoSigFork.name()),
            requires_capability(SigScheme).mark,
        ]
        assert not _check_markers_valid_for_fork(
            markers, _NoSigFork, _fork_by_name_table(_NoSigFork)
        )

    def test_multiple_capability_markers_compose_with_and(self) -> None:
        """Stacked capability markers fail the whole if any one fails."""

        @runtime_checkable
        class _Absent(Protocol):
            never_an_attribute_on_any_real_fork: ClassVar[object]

        markers = [
            requires_capability(SigScheme).mark,
            requires_capability(_Absent).mark,
        ]
        assert not _check_markers_valid_for_fork(markers, _LstarLikeFork, _fork_by_name_table())

    def test_dispatcher_raises_on_non_runtime_checkable_protocol(self) -> None:
        """The dispatcher's own guard rejects non-runtime-checkable Protocols."""

        class _NotRuntimeCheckable(Protocol):
            sig_scheme: ClassVar[object]

        # Bypass the helper's validation to exercise the dispatcher's guard.
        markers = [pytest.mark.requires.with_args(_NotRuntimeCheckable).mark]
        with pytest.raises(TypeError, match="runtime_checkable"):
            _check_markers_valid_for_fork(markers, _LstarLikeFork, _fork_by_name_table())
