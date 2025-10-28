"""Consensus layer pre-state generation."""

from typing import Any

from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.types import Bytes52, Uint64


def generate_pre_state(**kwargs: Any) -> State:
    """
    Generate a default pre-state for consensus tests.

    Args:
        **kwargs: Optional keyword arguments:
            - genesis_time: The genesis timestamp (defaults to Uint64(0)).
            - validators: Validators list (defaults to 4 validators with dummy pubkeys).

    Returns:
        State: A properly initialized consensus state.
    """
    genesis_time = kwargs.get("genesis_time", Uint64(0))

    # If validators not provided, create a default set of 4 validators with dummy pubkeys
    # TODO: Set an appropriate default here for test fixtures
    if "validators" not in kwargs:
        validators = Validators(data=[Validator(pubkey=Bytes52.zero()) for _ in range(4)])
    else:
        validators = kwargs["validators"]

    return State.generate_genesis(genesis_time=genesis_time, validators=validators)
