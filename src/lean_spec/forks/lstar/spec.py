"""Lstar fork — identity and construction facade."""

from typing import ClassVar

from lean_spec.forks.lstar.containers.block import Block

from ..protocol import ForkProtocol, SpecStateType
from .containers.state import State
from .store import Store


class LstarSpec(ForkProtocol):
    """Lstar fork."""

    NAME: ClassVar[str] = "lstar"
    VERSION: ClassVar[int] = 4
    GOSSIP_DIGEST: ClassVar[str] = "12345678"

    previous: ClassVar[type[ForkProtocol] | None] = None

    state_class: type[State] = State
    block_class: type[Block] = Block
    store_class: type[Store] = Store

    def upgrade_state(self, state: SpecStateType) -> State:
        """
        Lstar is the root fork: there is no predecessor, so no migration.

        Returns the input state unchanged.
        """
        assert isinstance(state, State)
        return state
