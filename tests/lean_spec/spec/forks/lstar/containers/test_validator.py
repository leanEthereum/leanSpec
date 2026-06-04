"""Tests for the GenesisConfig and Validator containers."""

import pytest
from pydantic import ValidationError

from lean_spec.spec.forks.lstar.containers import GenesisConfig, Validator
from lean_spec.spec.ssz import Bytes52, Uint64


class TestGenesisConfigImmutability:
    """Frozen-model semantics forbid post-construction mutation."""

    def test_assigning_genesis_time_raises(self) -> None:
        """Assigning a new genesis time on a constructed config raises."""
        config = GenesisConfig(genesis_time=Uint64(1_700_000_000))
        with pytest.raises(ValidationError, match="frozen"):
            config.genesis_time = Uint64(1_700_000_001)


class TestValidatorImmutability:
    """Frozen-model semantics forbid post-construction mutation."""

    def test_assigning_attestation_public_key_raises(self) -> None:
        """Assigning a new attestation key on a constructed validator raises."""
        validator = Validator(
            attestation_public_key=Bytes52.zero(),
            proposal_public_key=Bytes52.zero(),
        )
        with pytest.raises(ValidationError, match="frozen"):
            validator.attestation_public_key = Bytes52(b"\xff" * 52)

    def test_assigning_proposal_public_key_raises(self) -> None:
        """Assigning a new proposal key on a constructed validator raises."""
        validator = Validator(
            attestation_public_key=Bytes52.zero(),
            proposal_public_key=Bytes52.zero(),
        )
        with pytest.raises(ValidationError, match="frozen"):
            validator.proposal_public_key = Bytes52(b"\xff" * 52)
