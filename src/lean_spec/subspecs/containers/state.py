"""State Container."""

from typing import Dict, List

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import Annotated

from lean_spec.subspecs.chain import DEVNET_CONFIG
from lean_spec.types import Bytes32, Uint64, ValidatorIndex

from .block import BlockHeader
from .checkpoint import Checkpoint
from .config import Config


class State(BaseModel):
    """The main consensus state object."""

    model_config = ConfigDict(frozen=False, extra="forbid")

    # Configuration
    config: Config
    """The chain's configuration parameters."""

    # Slot and block tracking
    slot: Uint64
    """The current slot number."""

    latest_block_header: BlockHeader
    """The header of the most recent block."""

    # Fork choice
    latest_justified: Checkpoint
    """The latest justified checkpoint."""

    latest_finalized: Checkpoint
    """The latest finalized checkpoint."""

    # Historical data
    historical_block_hashes: Annotated[
        list[Bytes32],
        Field(max_length=DEVNET_CONFIG.historical_roots_limit),
    ]
    """A list of historical block root hashes."""

    justified_slots: Annotated[
        list[bool],
        Field(max_length=DEVNET_CONFIG.historical_roots_limit),
    ]
    """A bitfield indicating which historical slots were justified."""

    # Justification tracking (flattened for SSZ compatibility)
    justifications_roots: Annotated[
        list[Bytes32],
        Field(max_length=DEVNET_CONFIG.historical_roots_limit),
    ]
    """Roots of justified blocks."""

    justifications_validators: Annotated[
        list[bool],
        Field(
            max_length=(DEVNET_CONFIG.historical_roots_limit * DEVNET_CONFIG.historical_roots_limit)
        ),
    ]
    """A bitlist of validators who participated in justifications."""

    def is_proposer(self, validator_index: ValidatorIndex) -> bool:
        """Check if a validator is the proposer for the current slot."""
        return self.slot % self.config.num_validators == validator_index

    def get_justifications(self) -> Dict[Bytes32, List[bool]]:
        """
        Reconstructs the justification votes map from flattened state data.

        For Simple Serialize (SSZ) compatibility and on-chain efficiency, the
        consensus state stores justification data across two flattened lists:
          - `justifications_roots`: The list of block roots under consideration.
          - `justifications_validators`: A single, contiguous list containing
            the boolean votes for all roots.

        This method efficiently de-flattens this data into a more intuitive
        dictionary, mapping each root to its corresponding list of validator
        votes.

        Example:
            If `justifications_roots` = `[root_A, root_B]` and the validator
            limit is 4, `justifications_validators` would be a single list
            of 8 booleans (votes for A, then votes for B). This function
            would return: `{root_A: [votes...], root_B: [votes...]}`.

        Note:
            Client implementations may consider caching this computed map for
            performance, re-evaluating it only when the underlying state changes.

        Returns:
            A dictionary mapping each block root to a list of boolean votes.
            The index of each list corresponds to the validator index.
        """
        # Cache the validator registry limit for concise slicing calculations.
        #
        # This value determines the size of the block of votes for each root.
        limit = DEVNET_CONFIG.validator_registry_limit.as_int()

        # Build the entire justifications map.
        return {
            root: self.justifications_validators[i * limit : (i + 1) * limit]
            for i, root in enumerate(self.justifications_roots)
        }

    def set_justifications(self, justifications: Dict[Bytes32, List[bool]]) -> None:
        """
        Flattens and sets a justifications map on the state in-place.

        This method performs the inverse of `get_justifications`. It takes a
        human-readable dictionary of votes and serializes it into the two
        flattened lists required by the consensus state for SSZ compatibility.

        To ensure deterministic serialization, the roots are sorted before
        being flattened. The method also validates that each list of votes
        matches the required length.

        Args:
            justifications: A dictionary mapping block roots to their
                            corresponding list of validator votes.

        Returns:
            None. This method modifies the state object in-place.

        Raises:
            AssertionError: If any vote list's length does not match the
                            `validator_registry_limit`.
        """
        # It will store the deterministically sorted list of roots.
        new_roots: List[Bytes32] = []
        # It will store the single, concatenated list of all votes.
        flat_votes: List[bool] = []
        limit = DEVNET_CONFIG.validator_registry_limit.as_int()

        # Iterate through the roots in sorted order for deterministic output.
        for root in sorted(justifications.keys()):
            votes = justifications[root]
            # Check for an incorrect vote length.
            assert len(votes) == limit, f"Vote list for root {root.hex()} has incorrect length"

            # Append the root to the list of roots.
            new_roots.append(root)
            # Extend the flattened list with the votes for this root.
            flat_votes.extend(votes)

        # Modify the State instance in-place with the updated fields.
        self.justifications_roots = new_roots
        self.justifications_validators = flat_votes
