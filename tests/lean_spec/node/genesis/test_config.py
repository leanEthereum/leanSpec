"""Tests for the GenesisConfig class."""

from __future__ import annotations

import tempfile

import pytest
import yaml
from pydantic import ValidationError

from lean_spec.node.genesis import GenesisConfig
from lean_spec.spec.forks import ValidatorIndex
from lean_spec.spec.ssz import Bytes52, SSZValueError, Uint64


def _load(content: str) -> GenesisConfig:
    """Parse a YAML string into a GenesisConfig (test ergonomics helper)."""
    return GenesisConfig.model_validate(yaml.safe_load(content))


# Sample public_keys (52 bytes each, hex-encoded)
SAMPLE_PUBLIC_KEY_1 = "0x" + "00" * 52
SAMPLE_PUBLIC_KEY_2 = "0x" + "01" * 52
SAMPLE_PUBLIC_KEY_3 = "0x" + "02" * 52

SAMPLE_YAML = yaml.dump(
    {
        "GENESIS_TIME": 1704085200,
        "GENESIS_VALIDATORS": [
            {
                "attestation_public_key": SAMPLE_PUBLIC_KEY_1,
                "proposal_public_key": SAMPLE_PUBLIC_KEY_1,
            },
            {
                "attestation_public_key": SAMPLE_PUBLIC_KEY_2,
                "proposal_public_key": SAMPLE_PUBLIC_KEY_2,
            },
            {
                "attestation_public_key": SAMPLE_PUBLIC_KEY_3,
                "proposal_public_key": SAMPLE_PUBLIC_KEY_3,
            },
        ],
    }
)

# Real public_keys
PUBLIC_KEY_1 = (
    "0xe2a03c16122c7e0f940e2301aa460c54a2e1e8343968bb2782f26636f051e65e"
    "c589c858b9c7980b276ebe550056b23f0bdc3b5a"
)
PUBLIC_KEY_2 = (
    "0x0767e65924063f79ae92ee1953685f06718b1756cc665a299bd61b4b82055e37"
    "7237595d9a27887421b5233d09a50832db2f303d"
)
PUBLIC_KEY_3 = (
    "0xd4355005bc37f76f390dcd2bcc51677d8c6ab44e0cc64913fb84ad459789a311"
    "05bd9a69afd2690ffd737d22ec6e3b31d47a642f"
)


class TestGenesisConfigYamlLoading:
    """Tests for YAML loading functionality."""

    def test_load_from_yaml_string(self) -> None:
        """Parses YAML with UPPERCASE keys."""
        config = _load(SAMPLE_YAML)

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

    def test_public_keys_parsed_correctly(self) -> None:
        """PublicKeys are converted to Bytes52 instances."""
        config = _load(SAMPLE_YAML)

        for entry in config.genesis_validators:
            assert isinstance(entry.attestation_public_key, Bytes52)
            assert len(entry.attestation_public_key) == 52
            assert isinstance(entry.proposal_public_key, Bytes52)
            assert len(entry.proposal_public_key) == 52

    def test_public_key_without_0x_prefix(self) -> None:
        """Handles public_keys without 0x prefix (zeam format)."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": [
                    {"attestation_public_key": "00" * 52, "proposal_public_key": "00" * 52},
                    {"attestation_public_key": "01" * 52, "proposal_public_key": "01" * 52},
                ],
            }
        )
        config = _load(yaml_content)

        assert len(config.genesis_validators) == 2
        assert config.genesis_validators[0].attestation_public_key == Bytes52(b"\x00" * 52)


class TestGenesisConfigValidators:
    """Tests for validator conversion."""

    def test_to_validators_creates_indexed_list(self) -> None:
        """Validators have correct indices."""
        config = _load(SAMPLE_YAML)
        validators = config.to_validators()

        assert len(validators.data) == 3

        for i, validator in enumerate(validators.data):
            assert validator.index == ValidatorIndex(i)
            assert (
                validator.attestation_public_key
                == config.genesis_validators[i].attestation_public_key
            )
            assert validator.proposal_public_key == config.genesis_validators[i].proposal_public_key

    def test_empty_validators_list(self) -> None:
        """Handles empty validator list."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": [],
            }
        )
        config = _load(yaml_content)
        validators = config.to_validators()

        assert len(validators.data) == 0


class TestGenesisConfigValidation:
    """Tests for validation errors."""

    def test_invalid_public_key_raises_validation_error(self) -> None:
        """Rejects malformed hex."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": [
                    {
                        "attestation_public_key": "not_valid_hex",
                        "proposal_public_key": "not_valid_hex",
                    },
                ],
            }
        )
        with pytest.raises(ValidationError):
            _load(yaml_content)

    def test_wrong_length_public_key_raises_error(self) -> None:
        """Rejects public_keys with wrong length."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": [
                    {
                        "attestation_public_key": "0x0011223344",
                        "proposal_public_key": "0x0011223344",
                    },
                ],
            }
        )
        with pytest.raises(SSZValueError):
            _load(yaml_content)

    def test_missing_genesis_time_raises_error(self) -> None:
        """Requires GENESIS_TIME field."""
        yaml_content = yaml.dump(
            {
                "GENESIS_VALIDATORS": [
                    {
                        "attestation_public_key": SAMPLE_PUBLIC_KEY_1,
                        "proposal_public_key": SAMPLE_PUBLIC_KEY_1,
                    },
                ],
            }
        )
        with pytest.raises(ValidationError):
            _load(yaml_content)

    def test_missing_validators_raises_error(self) -> None:
        """Requires GENESIS_VALIDATORS field."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
            }
        )
        with pytest.raises(ValidationError):
            _load(yaml_content)

    def test_validators_not_a_list_raises_error(self) -> None:
        """Rejects GENESIS_VALIDATORS that is not a list."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": "not_a_list",
            }
        )
        with pytest.raises(ValidationError):
            _load(yaml_content)


class TestCrossClientFormat:
    """Tests for cross-client YAML config format compatibility."""

    def test_hex_prefixed_public_keys(self) -> None:
        """Loads config with 0x-prefixed hex public_keys (cross-client convention)."""
        yaml_content = yaml.dump(
            {
                "GENESIS_TIME": 1704085200,
                "GENESIS_VALIDATORS": [
                    {"attestation_public_key": PUBLIC_KEY_1, "proposal_public_key": PUBLIC_KEY_1},
                    {"attestation_public_key": PUBLIC_KEY_2, "proposal_public_key": PUBLIC_KEY_2},
                    {"attestation_public_key": PUBLIC_KEY_3, "proposal_public_key": PUBLIC_KEY_3},
                ],
            }
        )
        config = _load(yaml_content)

        assert config.genesis_time == Uint64(1704085200)
        assert len(config.genesis_validators) == 3

        # Verify all public_keys match expected values.
        expected_public_keys = [
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
        for entry, expected in zip(config.genesis_validators, expected_public_keys, strict=True):
            assert entry.attestation_public_key == expected
