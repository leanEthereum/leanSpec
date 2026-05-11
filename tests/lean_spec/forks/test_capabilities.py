"""Tests for fork capability Protocols and the @requires marker dispatch."""

from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol, runtime_checkable

import pytest
from framework.forks import BaseFork
from framework.pytest_plugins.filler import _check_markers_valid_for_fork

from lean_spec.forks import LstarSpec, SigScheme
from lean_spec.forks.protocol import ForkProtocol, SpecBlockType, SpecStateType
from lean_spec.subspecs.xmss.interface import TARGET_SIGNATURE_SCHEME
from lean_spec.types import ValidatorIndex


@dataclass(frozen=True)
class _Mark:
    """Minimal stand-in for pytest's Mark object.

    The dispatch helper only reads `.name` and `.args`, so this is enough
    to drive it without going through real pytest collection.
    """

    name: str
    args: tuple[Any, ...] = ()
    kwargs: dict[str, Any] = field(default_factory=dict)


class _NoSigSpec(ForkProtocol):
    """Synthetic fork that does NOT advertise SigScheme.

    Implements just enough abstract surface to be instantiable. Used to
    verify the @requires marker correctly deselects against forks lacking
    a capability.
    """

    NAME: ClassVar[str] = "no_sig"
    VERSION: ClassVar[int] = LstarSpec.VERSION + 1
    GOSSIP_DIGEST: ClassVar[str] = "deadbeef"
    previous: ClassVar[type[ForkProtocol] | None] = LstarSpec

    def upgrade_state(self, state: SpecStateType) -> SpecStateType:
        """Root-fork identity migration."""
        return state

    def generate_genesis(self, genesis_time: Any, validators: Any) -> SpecStateType:
        """Not exercised by capability dispatch."""
        raise NotImplementedError

    def create_store(
        self,
        state: SpecStateType,
        anchor_block: SpecBlockType,
        validator_id: ValidatorIndex | None,
    ) -> Any:
        """Not exercised by capability dispatch."""
        raise NotImplementedError


class _NoSigFork(BaseFork):
    """BaseFork wrapper exposing _NoSigSpec through spec_class()."""

    @classmethod
    def name(cls) -> str:
        return "_NoSigFork"

    @classmethod
    def spec_class(cls) -> type[_NoSigSpec]:
        return _NoSigSpec


class _LstarLikeFork(BaseFork):
    """Local BaseFork wrapper exposing LstarSpec.

    Mirrors `consensus_testing.forks.Lstar` but kept local so capability
    tests don't drag the entire consensus filler bootstrap into the
    import graph.
    """

    @classmethod
    def name(cls) -> str:
        return "_LstarLikeFork"

    @classmethod
    def spec_class(cls) -> type[LstarSpec]:
        return LstarSpec


def _fork_by_name_table(*forks: type[BaseFork]) -> Any:
    """Build a get_fork_by_name lookup over the given fork classes."""
    table = {fork.name(): fork for fork in forks}
    return table.get


class TestSigSchemeCapability:
    """SigScheme structurally identifies forks that expose an XMSS scheme."""

    def test_lstar_advertises_sigscheme(self) -> None:
        """LstarSpec satisfies SigScheme at runtime."""
        assert isinstance(LstarSpec(), SigScheme)

    def test_lstar_sig_scheme_is_target_scheme(self) -> None:
        """The bound scheme is the same TARGET_SIGNATURE_SCHEME singleton."""
        assert LstarSpec.sig_scheme is TARGET_SIGNATURE_SCHEME

    def test_fork_without_attribute_not_recognized(self) -> None:
        """A fork without sig_scheme is structurally rejected."""
        assert not isinstance(_NoSigSpec(), SigScheme)


class TestRequiresMarkerDispatch:
    """`requires(capability)` composes with the fork-range markers."""

    def test_no_markers_passes(self) -> None:
        """A test with no markers runs on any fork."""
        assert _check_markers_valid_for_fork([], _LstarLikeFork, _fork_by_name_table()) is True

    def test_requires_passes_when_capability_present(self) -> None:
        """LstarSpec advertises SigScheme — test is included."""
        markers = [_Mark("requires", (SigScheme,))]
        assert _check_markers_valid_for_fork(markers, _LstarLikeFork, _fork_by_name_table()) is True

    def test_requires_fails_when_capability_absent(self) -> None:
        """_NoSigSpec doesn't advertise SigScheme — test is deselected."""
        markers = [_Mark("requires", (SigScheme,))]
        assert _check_markers_valid_for_fork(markers, _NoSigFork, _fork_by_name_table()) is False

    def test_requires_composes_with_valid_until_and_passes(self) -> None:
        """`valid_until` AND `requires` both pass — test is included."""
        markers = [
            _Mark("valid_until", (_LstarLikeFork.name(),)),
            _Mark("requires", (SigScheme,)),
        ]
        assert (
            _check_markers_valid_for_fork(
                markers, _LstarLikeFork, _fork_by_name_table(_LstarLikeFork)
            )
            is True
        )

    def test_requires_composes_with_valid_until_and_fails_on_capability(self) -> None:
        """`valid_until` passes but capability missing — deselected."""
        markers = [
            _Mark("valid_until", (_NoSigFork.name(),)),
            _Mark("requires", (SigScheme,)),
        ]
        assert (
            _check_markers_valid_for_fork(markers, _NoSigFork, _fork_by_name_table(_NoSigFork))
            is False
        )

    def test_valid_at_short_circuit_still_checks_capability(self) -> None:
        """`valid_at` matches the fork name but capability missing — deselected."""
        markers = [
            _Mark("valid_at", (_NoSigFork.name(),)),
            _Mark("requires", (SigScheme,)),
        ]
        assert (
            _check_markers_valid_for_fork(markers, _NoSigFork, _fork_by_name_table(_NoSigFork))
            is False
        )

    def test_multiple_requires_markers_compose_with_and(self) -> None:
        """Stacked @requires markers all checked — one failing fails the whole."""

        @runtime_checkable
        class _Absent(Protocol):
            never_an_attribute_on_any_real_fork: ClassVar[object]

        markers = [
            _Mark("requires", (SigScheme,)),
            _Mark("requires", (_Absent,)),
        ]
        assert (
            _check_markers_valid_for_fork(markers, _LstarLikeFork, _fork_by_name_table()) is False
        )

    def test_requires_with_non_runtime_checkable_protocol_raises(self) -> None:
        """isinstance against a plain Protocol raises TypeError at check time."""

        class _NotRuntimeCheckable(Protocol):
            sig_scheme: ClassVar[object]

        markers = [_Mark("requires", (_NotRuntimeCheckable,))]
        with pytest.raises(TypeError, match="runtime_checkable"):
            _check_markers_valid_for_fork(markers, _LstarLikeFork, _fork_by_name_table())
