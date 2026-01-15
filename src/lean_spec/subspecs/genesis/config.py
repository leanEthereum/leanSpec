"""Genesis configuration loader."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field, field_validator

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

    1. **Time Synchronization**: All nodes must agree on when slots begin.
       The genesis time anchors the chain's internal clock to real-world time.
       From this moment, slots tick forward at fixed intervals. A node can
       compute "what slot is it now?" by measuring seconds since genesis.

    2. **Initial Trust**: Proof-of-stake requires an initial set of validators.
       These validators form the first committee that can produce and attest
       to blocks. Without them, no blocks could ever be finalized.

    The genesis block (slot 0) is implicit. It has no parent, no proposer,
    and no attestations. The first real block builds on top of this implicit
    origin, establishing the chain's cryptographic lineage.

    Example JSON configuration:

        {
            "GENESIS_TIME": 1704085200,
            "GENESIS_VALIDATORS": [
                "0xe2a03c1689769ae5f5762222b170b4a925f3f8e89340ed1cd31d31c134b0abc2...",
                "0x0767e659c1b61d30f65eadb7a309c4183d5d4c0f99e935737b89ce95dd1c4568..."
            ]
        }

    Field names use UPPERCASE to match the cross-client JSON convention.
    Pydantic aliases map them to snake_case Python attributes.
    """

    genesis_time: Uint64 = Field(alias="GENESIS_TIME")
    """
    Unix timestamp (seconds since 1970-01-01 UTC) when slot 0 begins.

    Anchors the chain's clock to real-world time.

    Nodes compute the current slot as: (now - genesis_time) / slot_duration.

    Immutable once the chain launches.
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
    def parse_hex_pubkeys(cls, v: list[str]) -> list[Bytes52]:
        """
        Convert hex strings to validated Bytes52 pubkeys.

        The JSON contains string representations.
        We parse them into typed Bytes52 objects for validation and use.

        Args:
            v: List of hex-encoded pubkey strings from JSON.

        Returns:
            List of validated Bytes52 pubkey objects.
        """
        return [Bytes52(pk) for pk in v]

    def to_validators(self) -> Validators:
        """
        Build the genesis validator set with assigned indices.

        Each validator needs an index for the registry.
        Indices are assigned sequentially starting from 0.

        Returns:
            Validators container ready for State creation.
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

        Returns:
            Fully initialized genesis State object.
        """
        return State.generate_genesis(self.genesis_time, self.to_validators())

    @classmethod
    def from_json_file(cls, path: Path | str) -> GenesisConfig:
        """
        Load configuration from a JSON file on disk.

        Use this to load shared genesis files distributed to all clients.

        Args:
            path: Path to genesis JSON file.

        Returns:
            Validated GenesisConfig instance.
        """
        with open(path) as f:
            data = json.load(f)
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, content: str) -> GenesisConfig:
        """
        Load configuration from a JSON string.

        Use this for testing or programmatic config generation.

        Args:
            content: JSON content as a string.

        Returns:
            Validated GenesisConfig instance.
        """
        return cls.model_validate_json(content)
