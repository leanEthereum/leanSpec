"""Consensus layer pre-state generation."""

import os
from typing import Any

from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.types import Uint64

from ..keys import get_shared_key_manager


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

    lean_env = os.environ.get("LEAN_ENV", "test").lower()
    key_manager = get_shared_key_manager(lean_env)
    available_keys = len(key_manager)

    assert num_validators <= available_keys, (
        "Not enough keys to generate state",
        f"Expecting {num_validators} validators but the key manager has only {available_keys} keys",
    )

    validators = Validators(
        data=[
            Validator(pubkey=key_manager[Uint64(i)].public.encode_bytes(), index=Uint64(i))
            for i in range(num_validators)
        ]
    )

    return State.generate_genesis(genesis_time=genesis_time, validators=validators)
