"""Tests for the GenesisConfig class."""

from __future__ import annotations

import json
import tempfile

import pytest
from pydantic import ValidationError

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.genesis import GenesisConfig
from lean_spec.types import Bytes52, SSZValueError, Uint64

# Sample pubkeys (52 bytes each, hex-encoded)
SAMPLE_PUBKEY_1 = "0x" + "00" * 52
SAMPLE_PUBKEY_2 = "0x" + "01" * 52
SAMPLE_PUBKEY_3 = "0x" + "02" * 52

SAMPLE_JSON = json.dumps(
    {
        "GENESIS_TIME": 1704085200,
        "GENESIS_VALIDATORS": [SAMPLE_PUBKEY_1, SAMPLE_PUBKEY_2, SAMPLE_PUBKEY_3],
    }
)

# Real pubkeys from ream config (split for line length)
REAM_PUBKEY_1 = (
    "0xe2a03c16122c7e0f940e2301aa460c54a2e1e8343968bb2782f26636f051e65e"
    "c589c858b9c7980b276ebe550056b23f0bdc3b5a"
)
REAM_PUBKEY_2 = (
    "0x0767e65924063f79ae92ee1953685f06718b1756cc665a299bd61b4b82055e37"
    "7237595d9a27887421b5233d09a50832db2f303d"
)
REAM_PUBKEY_3 = (
    "0xd4355005bc37f76f390dcd2bcc51677d8c6ab44e0cc64913fb84ad459789a311"
    "05bd9a69afd2690ffd737d22ec6e3b31d47a642f"
)


class TestGenesisConfigJsonLoading:
    """Tests for JSON loading functionality."""

    def test_load_from_json_string(self) -> None:
        """Parses JSON with UPPERCASE keys."""
        config = GenesisConfig.from_json(SAMPLE_JSON)

        assert config.genesis_time == Uint64(1704085200)
        assert len(config.genesis_validators) == 3

    def test_load_from_json_file(self) -> None:
        """Loads config from file path."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(SAMPLE_JSON)
            f.flush()

            config = GenesisConfig.from_json_file(f.name)

            assert config.genesis_time == Uint64(1704085200)
            assert len(config.genesis_validators) == 3

    def test_pubkeys_parsed_correctly(self) -> None:
        """Pubkeys are converted to Bytes52 instances."""
        config = GenesisConfig.from_json(SAMPLE_JSON)

        for pk in config.genesis_validators:
            assert isinstance(pk, Bytes52)
            assert len(pk) == 52

    def test_pubkey_without_0x_prefix(self) -> None:
        """Handles pubkeys without 0x prefix (zeam format)."""
        json_content = json.dumps(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": ["00" * 52, "01" * 52],
            }
        )
        config = GenesisConfig.from_json(json_content)

        assert len(config.genesis_validators) == 2
        assert config.genesis_validators[0] == Bytes52(b"\x00" * 52)


class TestGenesisConfigValidators:
    """Tests for validator conversion."""

    def test_to_validators_creates_indexed_list(self) -> None:
        """Validators have correct indices."""
        config = GenesisConfig.from_json(SAMPLE_JSON)
        validators = config.to_validators()

        assert len(validators.data) == 3

        for i, validator in enumerate(validators.data):
            assert validator.index == Uint64(i)
            assert validator.pubkey == config.genesis_validators[i]

    def test_empty_validators_list(self) -> None:
        """Handles empty validator list."""
        json_content = json.dumps(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": [],
            }
        )
        config = GenesisConfig.from_json(json_content)
        validators = config.to_validators()

        assert len(validators.data) == 0


class TestGenesisConfigState:
    """Tests for state creation."""

    def test_create_state_returns_valid_genesis(self) -> None:
        """State has correct genesis time and validators."""
        config = GenesisConfig.from_json(SAMPLE_JSON)
        state = config.create_state()

        # Genesis time is stored in the state's config.
        assert state.config.genesis_time == config.genesis_time
        assert state.slot == Slot(0)
        assert len(state.validators.data) == 3


class TestGenesisConfigValidation:
    """Tests for validation errors."""

    def test_invalid_pubkey_raises_validation_error(self) -> None:
        """Rejects malformed hex."""
        json_content = json.dumps(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": ["not_valid_hex"],
            }
        )
        with pytest.raises(ValidationError):
            GenesisConfig.from_json(json_content)

    def test_wrong_length_pubkey_raises_error(self) -> None:
        """Rejects pubkeys with wrong length."""
        json_content = json.dumps(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": ["0x0011223344"],
            }
        )
        with pytest.raises(SSZValueError):
            GenesisConfig.from_json(json_content)

    def test_missing_genesis_time_raises_error(self) -> None:
        """Requires GENESIS_TIME field."""
        json_content = json.dumps(
            {
                "GENESIS_VALIDATORS": [SAMPLE_PUBKEY_1],
            }
        )
        with pytest.raises(ValidationError):
            GenesisConfig.from_json(json_content)

    def test_missing_validators_raises_error(self) -> None:
        """Requires GENESIS_VALIDATORS field."""
        json_content = json.dumps(
            {
                "GENESIS_TIME": 1704085200,
            }
        )
        with pytest.raises(ValidationError):
            GenesisConfig.from_json(json_content)


class TestReamCompatibility:
    """Tests for compatibility with ream config format."""

    def test_ream_format_config(self) -> None:
        """Loads config in ream format with 0x-prefixed pubkeys."""
        # This matches the format used in ream/bin/ream/assets/lean/config.yaml
        json_content = json.dumps(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": [REAM_PUBKEY_1, REAM_PUBKEY_2, REAM_PUBKEY_3],
            }
        )
        config = GenesisConfig.from_json(json_content)

        assert config.genesis_time == Uint64(1704085200)
        assert len(config.genesis_validators) == 3

        # Verify first pubkey matches.
        expected_first = Bytes52(
            bytes.fromhex(
                "e2a03c16122c7e0f940e2301aa460c54a2e1e8343968bb2782f26636f051e65e"
                "c589c858b9c7980b276ebe550056b23f0bdc3b5a"
            )
        )
        assert config.genesis_validators[0] == expected_first
