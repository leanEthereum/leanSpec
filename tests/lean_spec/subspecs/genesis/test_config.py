"""Tests for the GenesisConfig class."""

from __future__ import annotations

import tempfile

import pytest
import yaml
from pydantic import ValidationError

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.genesis import GenesisConfig
from lean_spec.types import Bytes52, SSZValueError, Uint64

# Sample pubkeys (52 bytes each, hex-encoded)
SAMPLE_PUBKEY_1 = "0x" + "00" * 52
SAMPLE_PUBKEY_2 = "0x" + "01" * 52
SAMPLE_PUBKEY_3 = "0x" + "02" * 52

SAMPLE_YAML = yaml.dump(
    {
        "GENESIS_TIME": 1704085200,
        "GENESIS_VALIDATORS": [SAMPLE_PUBKEY_1, SAMPLE_PUBKEY_2, SAMPLE_PUBKEY_3],
    }
)

# Real pubkeys
PUBKEY_1 = (
    "0xe2a03c16122c7e0f940e2301aa460c54a2e1e8343968bb2782f26636f051e65e"
    "c589c858b9c7980b276ebe550056b23f0bdc3b5a"
)
PUBKEY_2 = (
    "0x0767e65924063f79ae92ee1953685f06718b1756cc665a299bd61b4b82055e37"
    "7237595d9a27887421b5233d09a50832db2f303d"
)
PUBKEY_3 = (
    "0xd4355005bc37f76f390dcd2bcc51677d8c6ab44e0cc64913fb84ad459789a311"
    "05bd9a69afd2690ffd737d22ec6e3b31d47a642f"
)


class TestGenesisConfigYamlLoading:
    """Tests for YAML loading functionality."""

    def test_load_from_yaml_string(self) -> None:
        """Parses YAML with UPPERCASE keys."""
        config = GenesisConfig.from_yaml(SAMPLE_YAML)

        assert config.genesis_time == Uint64(1704085200)
        assert len(config.genesis_validators) == 3

    def test_load_from_yaml_file(self) -> None:
        """Loads config from file path."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(SAMPLE_YAML)
            f.flush()

            config = GenesisConfig.from_yaml_file(f.name)

            assert config.genesis_time == Uint64(1704085200)
            assert len(config.genesis_validators) == 3

    def test_pubkeys_parsed_correctly(self) -> None:
        """Pubkeys are converted to Bytes52 instances."""
        config = GenesisConfig.from_yaml(SAMPLE_YAML)

        for pk in config.genesis_validators:
            assert isinstance(pk, Bytes52)
            assert len(pk) == 52

    def test_pubkey_without_0x_prefix(self) -> None:
        """Handles pubkeys without 0x prefix (zeam format)."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": ["00" * 52, "01" * 52],
            }
        )
        config = GenesisConfig.from_yaml(yaml_content)

        assert len(config.genesis_validators) == 2
        assert config.genesis_validators[0] == Bytes52(b"\x00" * 52)


class TestGenesisConfigValidators:
    """Tests for validator conversion."""

    def test_to_validators_creates_indexed_list(self) -> None:
        """Validators have correct indices."""
        config = GenesisConfig.from_yaml(SAMPLE_YAML)
        validators = config.to_validators()

        assert len(validators.data) == 3

        for i, validator in enumerate(validators.data):
            assert validator.index == Uint64(i)
            assert validator.pubkey == config.genesis_validators[i]

    def test_empty_validators_list(self) -> None:
        """Handles empty validator list."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": [],
            }
        )
        config = GenesisConfig.from_yaml(yaml_content)
        validators = config.to_validators()

        assert len(validators.data) == 0


class TestGenesisConfigState:
    """Tests for state creation."""

    def test_create_state_returns_valid_genesis(self) -> None:
        """State has correct genesis time and validators."""
        config = GenesisConfig.from_yaml(SAMPLE_YAML)
        state = config.create_state()

        # Genesis time is stored in the state's config.
        assert state.config.genesis_time == config.genesis_time
        assert state.slot == Slot(0)
        assert len(state.validators.data) == 3


class TestGenesisConfigValidation:
    """Tests for validation errors."""

    def test_invalid_pubkey_raises_validation_error(self) -> None:
        """Rejects malformed hex."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": ["not_valid_hex"],
            }
        )
        with pytest.raises(ValidationError):
            GenesisConfig.from_yaml(yaml_content)

    def test_wrong_length_pubkey_raises_error(self) -> None:
        """Rejects pubkeys with wrong length."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": ["0x0011223344"],
            }
        )
        with pytest.raises(SSZValueError):
            GenesisConfig.from_yaml(yaml_content)

    def test_missing_genesis_time_raises_error(self) -> None:
        """Requires GENESIS_TIME field."""
        yaml_content = yaml.dump(
            {
                "GENESIS_VALIDATORS": [SAMPLE_PUBKEY_1],
            }
        )
        with pytest.raises(ValidationError):
            GenesisConfig.from_yaml(yaml_content)

    def test_missing_validators_raises_error(self) -> None:
        """Requires GENESIS_VALIDATORS field."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
            }
        )
        with pytest.raises(ValidationError):
            GenesisConfig.from_yaml(yaml_content)

    def test_validators_not_a_list_raises_error(self) -> None:
        """Rejects GENESIS_VALIDATORS that is not a list."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": "not_a_list",
            }
        )
        with pytest.raises(ValidationError, match="must be a list"):
            GenesisConfig.from_yaml(yaml_content)

    def test_num_validators_mismatch_raises_error(self) -> None:
        """Rejects config where NUM_VALIDATORS does not match actual count."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "NUM_VALIDATORS": 5,
                "GENESIS_VALIDATORS": [SAMPLE_PUBKEY_1, SAMPLE_PUBKEY_2],
            }
        )
        with pytest.raises(ValidationError, match="does not match"):
            GenesisConfig.from_yaml(yaml_content)

    def test_num_validators_correct_value_accepted(self) -> None:
        """Accepts config where NUM_VALIDATORS matches actual count."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "NUM_VALIDATORS": 2,
                "GENESIS_VALIDATORS": [SAMPLE_PUBKEY_1, SAMPLE_PUBKEY_2],
            }
        )
        config = GenesisConfig.from_yaml(yaml_content)

        assert config.num_validators == 2
        assert len(config.genesis_validators) == 2


class TestCrossClientFormat:
    """Tests for cross-client YAML config format compatibility."""

    def test_hex_prefixed_pubkeys(self) -> None:
        """Loads config with 0x-prefixed hex pubkeys (cross-client convention)."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": [PUBKEY_1, PUBKEY_2, PUBKEY_3],
            }
        )
        config = GenesisConfig.from_yaml(yaml_content)

        assert config.genesis_time == Uint64(1704085200)
        assert len(config.genesis_validators) == 3

        # Verify all pubkeys match expected values.
        expected_pubkeys = [
            Bytes52(
                bytes.fromhex(
                    "e2a03c16122c7e0f940e2301aa460c54a2e1e8343968bb2782f26636f051e65e"
                    "c589c858b9c7980b276ebe550056b23f0bdc3b5a"
                )
            ),
            Bytes52(
                bytes.fromhex(
                    "0767e65924063f79ae92ee1953685f06718b1756cc665a299bd61b4b82055e37"
                    "7237595d9a27887421b5233d09a50832db2f303d"
                )
            ),
            Bytes52(
                bytes.fromhex(
                    "d4355005bc37f76f390dcd2bcc51677d8c6ab44e0cc64913fb84ad459789a311"
                    "05bd9a69afd2690ffd737d22ec6e3b31d47a642f"
                )
            ),
        ]
        assert config.genesis_validators == expected_pubkeys
