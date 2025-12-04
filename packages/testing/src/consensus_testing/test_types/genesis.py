"""Consensus layer pre-state generation."""

from functools import lru_cache
from typing import Any

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.types import Uint64

from ..keys import XmssKeyManager


@lru_cache(maxsize=1)
def _get_shared_key_manager() -> XmssKeyManager:
    """
    Get or create the shared XMSS key manager for reusing keys across tests.

    Uses functools.lru_cache to create a singleton instance that's shared
    across all test fixture generations within a session. This optimizes
    performance by reusing keys when possible.

    Returns:
        Shared XmssKeyManager instance with max_slot=10.
    """
    return XmssKeyManager(max_slot=Slot(10))


def generate_pre_state(**kwargs: Any) -> State:
    """
    Generate a default pre-state for consensus tests.

    Args:
        **kwargs: Optional keyword arguments:
            - genesis_time: The genesis timestamp (defaults to Uint64(0)).
            - num_validators: Number of validators (defaults to 4 validators).

    Returns:
        State: A properly initialized consensus state.
    """
    genesis_time = kwargs.get("genesis_time", Uint64(0))
    num_validators = kwargs.get("num_validators", 4)
    key_manager = _get_shared_key_manager()

    validators = Validators(
        data=[
            Validator(pubkey=key_manager[Uint64(i)].public.encode_bytes(), index=Uint64(i))
            for i in range(num_validators)
        ]
    )

    return State.generate_genesis(genesis_time=genesis_time, validators=validators)
