"""State Container."""

from pydantic import Field
from typing_extensions import Annotated

from lean_spec.subspecs.chain import DEVNET_CONFIG
from lean_spec.types import Bytes32, StrictBaseModel, Uint64, ValidatorIndex

from .block import BlockHeader
from .checkpoint import Checkpoint
from .config import Config


class State(StrictBaseModel):
    """The main consensus state object."""

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
