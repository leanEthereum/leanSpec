"""Genesis configuration loader.

Loads genesis configuration from YAML files compatible with ream and zeam.

The expected YAML format matches the cross-client convention:

    GENESIS_TIME: 1704085200
    GENESIS_VALIDATORS:
    - 0xe2a03c16122c7e0f940e2301aa460c54a2e1e8343968bb2782f26636f051e65e...
    - 0x0767e65924063f79ae92ee1953685f06718b1756cc665a299bd61b4b82055e37...
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator, model_validator

from lean_spec.subspecs.containers import State, Validator
from lean_spec.subspecs.containers.state import Validators
from lean_spec.types import Bytes52, StrictBaseModel, Uint64


class GenesisConfig(StrictBaseModel):
    """
    Configuration that establishes the birth of an Ethereum consensus chain.

    Genesis is the shared starting point for all participants in the network.
    Without a common genesis, nodes cannot agree on the chain's history.
    Every block traces its ancestry back to this origin.

    The genesis configuration solves two fundamental coordination problems:

    - Time Synchronization: All nodes agree on when slots begin
    - Initial Trust: Bootstrap validators that can produce and attest blocks

    Field names use UPPERCASE to match cross-client YAML convention.
    Pydantic aliases map them to snake_case Python attributes.
    """

    genesis_time: Uint64 = Field(alias="GENESIS_TIME")
    """
    Unix timestamp (seconds since 1970-01-01 UTC) when slot 0 begins.

    Anchors the chain's clock to real-world time.

    Nodes compute the current slot as: (now - genesis_time) / slot_duration.

    Immutable once the chain launches.
    """

    num_validators: int | None = Field(default=None, alias="NUM_VALIDATORS")
    """
    Number of validators (optional, for ream compatibility).

    This field is informational and may be included in ream config files.
    The actual validator count is derived from the genesis_validators list.
    """

    genesis_validators: list[Bytes52] = Field(alias="GENESIS_VALIDATORS")
    """
    Public keys of validators trusted to secure the chain from slot 0.

    Bootstrap the proof-of-stake mechanism.

    These validators can:

    - Propose the first blocks
    - Cast attestations for justification/finalization
    - Form the supermajority needed for consensus

    Each key is 52 bytes (XMSS format).

    Security note: 2/3+ collusion controls the chain until new validators join.
    """

    @field_validator("genesis_validators", mode="before")
    @classmethod
    def parse_hex_pubkeys(cls, v: Any) -> list[Bytes52]:
        """
        Convert hex strings or integers to validated Bytes52 pubkeys.

        YAML parsers may interpret 0x-prefixed values as integers.
        Handles both string and integer inputs for compatibility.
        """
        if not isinstance(v, list):
            raise ValueError(f"genesis_validators must be a list, got {type(v).__name__}")

        result = []
        for pk in v:
            if isinstance(pk, int):
                # YAML parsed 0x... as integer, convert back to hex string.
                # Pad to 52 bytes (104 hex chars).
                pk = f"0x{pk:0104x}"
            result.append(Bytes52(pk))
        return result

    @model_validator(mode="after")
    def validate_num_validators_consistency(self) -> GenesisConfig:
        """Verify num_validators matches actual count when provided."""
        if self.num_validators is not None:
            actual_count = len(self.genesis_validators)
            if self.num_validators != actual_count:
                raise ValueError(
                    f"NUM_VALIDATORS ({self.num_validators}) does not match "
                    f"actual validator count ({actual_count})"
                )
        return self

    def to_validators(self) -> Validators:
        """
        Build the genesis validator set with assigned indices.

        Each validator needs an index for the registry.
        Indices are assigned sequentially starting from 0.
        """
        return Validators(
            data=[
                Validator(pubkey=pk, index=Uint64(i))
                for i, pk in enumerate(self.genesis_validators)
            ]
        )

    def create_state(self) -> State:
        """
        Generate the complete genesis state from this configuration.

        Combines genesis time and validator set to create the initial
        consensus state. This state becomes slot 0 for the chain.
        """
        return State.generate_genesis(self.genesis_time, self.to_validators())

    @classmethod
    def from_yaml_file(cls, path: Path | str) -> GenesisConfig:
        """
        Load configuration from a YAML file.

        Use this to load shared genesis files distributed to all clients.
        Compatible with ream's config.yaml format.

        Raises:
            FileNotFoundError: If the file does not exist.
            yaml.YAMLError: If the file is not valid YAML.
            pydantic.ValidationError: If the data fails validation.
        """
        path = Path(path)
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)

    @classmethod
    def from_yaml(cls, content: str) -> GenesisConfig:
        """
        Load configuration from a YAML string.

        Useful for testing or programmatic config generation.
        """
        data = yaml.safe_load(content)
        return cls.model_validate(data)
