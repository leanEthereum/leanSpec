"""Lstar fork — identity and construction facade."""

from typing import ClassVar

from lean_spec.forks.lstar.containers.block import Block

from ..protocol import ForkProtocol
from .containers.state import State
from .store import Store


class LstarSpec(ForkProtocol):
    """Lstar fork."""

    NAME: ClassVar[str] = "lstar"
    VERSION: ClassVar[int] = 4
    NETWORK_NAME: ClassVar[str] = "devnet0"

    previous: ClassVar[type[ForkProtocol] | None] = None

    state_class: ClassVar[type[State]] = State
    block_class: ClassVar[type[Block]] = Block
    store_class: ClassVar[type[Store]] = Store

    def upgrade_state(self, state: State) -> State:
        """
        Lstar is the root fork: there is no predecessor, so no migration.

        Returns the input state unchanged.
        """
        return state
