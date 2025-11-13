"""Helpers for the State container."""

from typing import Dict, List

from lean_spec.subspecs.containers.state.types import (
    JustificationRoots,
    JustificationValidators,
)
from lean_spec.types import Boolean, Bytes32


def get_justifications_map(
    justifications_roots: JustificationRoots,
    justifications_validators: JustificationValidators,
    validator_count: int,
) -> Dict[Bytes32, List[Boolean]]:
    """
    Reconstruct the justifications map from the state's flat data structures.

    Parameters
    ----------
    justifications_roots : JustificationRoots
        The block roots in alphabetical order.
    justifications_validators : JustificationValidators
        The list of validator justifications for each block root concatenated in the same order
        as the list of block roots.
    validator_count : int
        The number of validators in the state.

    Returns:
    -------
    Dict[Bytes32, List[Boolean]]
        A mapping from a block root to the list of validator justifications for that root.
    """
    # No justified roots means no justifications to reconstruct.
    if not justifications_roots:
        return {}

    # # Extract the flattened validator justifications.
    # flat_justifications = list(justifications_validators)

    # Reconstruct the map: each root gets its corresponding justification slice.
    return {
        root: justifications_validators[i * validator_count : (i + 1) * validator_count]
        for i, root in enumerate(justifications_roots)
    }


def flatten_justifications_map(
    justifications_map: Dict[Bytes32, List[Boolean]], validator_count: int
) -> (JustificationRoots, JustificationValidators):
    """
    Flatten a map of validator justifications into the state's flat data structures
    for SSZ compatibility.

    Parameters
    ----------
    justifications_map : Dict[Bytes32, List[Boolean]]
        A mapping from a block root to the list of validator justifications for that root.
    validator_count : int
        The number of validators in the state.

    Returns:
    -------
    JustificationRoots
        The block roots in alphabetical order.
    JustificationValidators
        The list of validator justifications for each block root concatenated in the same order
        as the list of block roots.
    """
    # Build the flattened lists from the map, with sorted keys for deterministic order.
    roots_list = []
    justifications_list = []

    for root in sorted(justifications_map.keys()):
        justifications = justifications_map[root]

        # Validate that the justifications list has the expected length.
        if len(justifications) != validator_count:
            raise AssertionError(f"Justifications list for root {root.hex()} has incorrect length")

        # Add the root to the roots list.
        roots_list.append(root)
        # Extend the flattened list with the justifications for this root.
        justifications_list.extend(justifications)

    # Return a new state object with the updated fields.
    return JustificationRoots(data=roots_list), JustificationValidators(data=justifications_list)
