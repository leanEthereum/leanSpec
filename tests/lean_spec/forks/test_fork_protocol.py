"""Tests for the multi-fork architecture."""

import ast
from typing import ClassVar

import pytest

from lean_spec.forks import (
    DEFAULT_REGISTRY,
    FORK_SEQUENCE,
    ForkProtocol,
    ForkRegistry,
    LstarSpec,
    protocol,
)
from lean_spec.forks.lstar.containers.block import Block
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.state import State
from lean_spec.types import Uint64
from tests.lean_spec.helpers.builders import make_validators


class _NextSpec(LstarSpec):
    """Synthetic successor fork. Used only by registry tests."""

    NAME: ClassVar[str] = "next"
    VERSION: ClassVar[int] = LstarSpec.VERSION + 1
    previous: ClassVar[type[ForkProtocol] | None] = LstarSpec


class TestForkProtocolGeneric:
    """ForkProtocol must not hard-reference any devnet."""

    def test_cannot_instantiate_directly(self) -> None:
        """ForkProtocol is abstract; concrete forks must implement upgrade_state."""
        with pytest.raises(TypeError, match="abstract"):
            ForkProtocol()  # type: ignore[abstract]

    def test_protocol_module_imports_no_devnet_package(self) -> None:
        """The protocol module must not import any devnet package."""
        source = protocol.__file__
        assert source is not None
        tree = ast.parse(open(source).read())

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert "devnet" not in mod, f"Forbidden import from {mod}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert "devnet" not in alias.name, f"Forbidden import of {alias.name}"


class TestLstarSpec:
    """Tests for the LstarSpec fork implementation."""

    def test_identity(self) -> None:
        """LstarSpec reports stable name and version."""
        assert LstarSpec.NAME == "lstar"
        assert LstarSpec.VERSION == 4

    def test_network_name(self) -> None:
        """LstarSpec carries the gossipsub network name as fork metadata."""
        assert LstarSpec.NETWORK_NAME == "devnet0"

    def test_previous_is_none(self) -> None:
        """LstarSpec is the root of the upgrade chain."""
        assert LstarSpec.previous is None

    def test_is_fork_protocol(self) -> None:
        """LstarSpec is a ForkProtocol instance."""
        assert isinstance(LstarSpec(), ForkProtocol)

    def test_binds_container_types(self) -> None:
        """LstarSpec exposes State, Block, and Store as ClassVars."""
        assert LstarSpec.state_class is State
        assert LstarSpec.block_class is Block

    def test_generate_genesis(self) -> None:
        """LstarSpec generates a valid genesis state via its State class."""
        fork = LstarSpec()
        validators = make_validators(4)
        state = fork.generate_genesis(Uint64(0), validators)
        assert state.slot == Slot(0)
        assert len(state.validators) == 4

    def test_upgrade_state_is_identity(self) -> None:
        """Lstar is the root fork: upgrade_state returns the input unchanged."""
        fork = LstarSpec()
        validators = make_validators(4)
        state = fork.generate_genesis(Uint64(0), validators)
        assert fork.upgrade_state(state) is state


class TestForkRegistry:
    """Tests for the ForkRegistry."""

    def test_default_registry_holds_registered_forks(self) -> None:
        """DEFAULT_REGISTRY reflects FORK_SEQUENCE."""
        assert DEFAULT_REGISTRY.current.NAME == FORK_SEQUENCE[-1].NAME

    def test_current_returns_latest(self) -> None:
        """ForkRegistry.current returns the highest-VERSION fork."""
        registry = ForkRegistry([LstarSpec(), _NextSpec()])
        assert registry.current.NAME == _NextSpec.NAME

    def test_get_fork_by_name(self) -> None:
        """ForkRegistry.get_fork looks up by fork NAME."""
        registry = ForkRegistry([LstarSpec(), _NextSpec()])
        assert registry.get_fork("lstar").NAME == "lstar"
        assert registry.get_fork("next").NAME == "next"

    def test_get_fork_unknown_raises(self) -> None:
        """ForkRegistry.get_fork raises KeyError for unknown forks."""
        registry = ForkRegistry([LstarSpec()])
        with pytest.raises(KeyError, match="Unknown fork: 'missing'"):
            registry.get_fork("missing")

    def test_empty_forks_raises(self) -> None:
        """ForkRegistry requires at least one fork."""
        with pytest.raises(ValueError, match="at least one fork"):
            ForkRegistry([])

    def test_non_monotonic_version_rejected(self) -> None:
        """ForkRegistry rejects forks whose versions do not strictly increase."""
        with pytest.raises(ValueError, match="strictly increasing VERSION"):
            ForkRegistry([_NextSpec(), LstarSpec()])

    def test_duplicate_version_rejected(self) -> None:
        """ForkRegistry rejects two forks sharing a VERSION."""

        class ShadowSpec(LstarSpec):
            NAME = "shadow"
            VERSION = LstarSpec.VERSION

        with pytest.raises(ValueError, match="strictly increasing VERSION"):
            ForkRegistry([LstarSpec(), ShadowSpec()])

    def test_duplicate_name_rejected(self) -> None:
        """ForkRegistry rejects two forks sharing a NAME."""

        class TwinSpec(LstarSpec):
            NAME = LstarSpec.NAME
            VERSION = LstarSpec.VERSION + 10

        with pytest.raises(ValueError, match="names must be unique"):
            ForkRegistry([LstarSpec(), TwinSpec()])
