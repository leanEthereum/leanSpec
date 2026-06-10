"""Tests for Validator Registry."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from consensus_testing.keys import XmssKeyManager
from lean_spec.node.validator import ValidatorRegistry
from lean_spec.node.validator.registry import (
    ValidatorEntry,
    ValidatorManifest,
    ValidatorManifestEntry,
    load_node_validator_mapping,
)
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.ssz import Bytes52
from lean_spec.spec.ssz.exceptions import SSZValueError


def registry_state(registry: ValidatorRegistry) -> dict[ValidatorIndex, tuple[object, object]]:
    """Map each registry index to its (attestation_secret_key, proposal_secret_key) pair."""
    index_to_secret_keys: dict[ValidatorIndex, tuple[object, object]] = {}
    for index in registry.indices():
        validator_entry = registry.get(index)
        assert validator_entry is not None, (
            f"Registry contains index {index} but get() returned None"
        )
        index_to_secret_keys[index] = (
            validator_entry.attestation_secret_key,
            validator_entry.proposal_secret_key,
        )
    return index_to_secret_keys


@pytest.fixture
def km() -> XmssKeyManager:
    """Key manager for registry tests."""
    return XmssKeyManager.shared(max_slot=Slot(10))


def _minimal_manifest_dict(
    *,
    num_validators: int = 0,
    validators: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Return a minimal valid manifest dict, optionally with validators."""
    return {
        "key_scheme": "SIGTopLevelTargetSumLifetime32Dim64Base8",
        "hash_function": "Poseidon2",
        "encoding": "TargetSum",
        "lifetime": 32,
        "log_num_active_epochs": 5,
        "num_active_epochs": 32,
        "num_validators": num_validators,
        "validators": validators or [],
    }


def _manifest_entry_dict(index: int, suffix: str = "") -> dict[str, object]:
    """Return a manifest entry dict for a validator at the given index."""
    return {
        "index": index,
        "attestation_public_key_hex": "0x" + f"{index:02d}" * 52,
        "proposal_public_key_hex": "0x" + f"{index:02d}" * 52,
        "attestation_private_key_file": f"att_key_{index}{suffix}.ssz",
        "proposal_private_key_file": f"prop_key_{index}{suffix}.ssz",
    }


class TestValidatorEntry:
    """Tests for ValidatorEntry frozen dataclass."""

    def test_construction_stores_all_fields(self, km: XmssKeyManager) -> None:
        """All three fields are accessible after construction."""
        kp = km[ValidatorIndex(7)]
        validator_entry = ValidatorEntry(
            index=ValidatorIndex(7),
            attestation_secret_key=kp.attestation_keypair.secret_key,
            proposal_secret_key=kp.proposal_keypair.secret_key,
        )

        assert validator_entry == ValidatorEntry(
            index=ValidatorIndex(7),
            attestation_secret_key=kp.attestation_keypair.secret_key,
            proposal_secret_key=kp.proposal_keypair.secret_key,
        )


class TestValidatorManifestEntry:
    """Tests for ValidatorManifestEntry Pydantic model."""

    def test_construction_stores_all_fields(self) -> None:
        """All fields are stored and accessible after construction."""
        manifest_entry = ValidatorManifestEntry(
            index=ValidatorIndex(3),
            attestation_public_key_hex=Bytes52("0x" + "aa" * 52),
            proposal_public_key_hex=Bytes52("0x" + "bb" * 52),
            attestation_private_key_file="att.ssz",
            proposal_private_key_file="prop.ssz",
        )

        assert manifest_entry == ValidatorManifestEntry(
            index=ValidatorIndex(3),
            attestation_public_key_hex=Bytes52("0x" + "aa" * 52),
            proposal_public_key_hex=Bytes52("0x" + "bb" * 52),
            attestation_private_key_file="att.ssz",
            proposal_private_key_file="prop.ssz",
        )

    def test_integer_public_key_rejected(self) -> None:
        """Integer public_keys are rejected — only valid 52-byte hex strings accepted."""
        with pytest.raises((TypeError, ValidationError)):
            ValidatorManifestEntry(
                index=ValidatorIndex(0),
                attestation_public_key_hex=0x123,  # type: ignore[arg-type]
                proposal_public_key_hex=Bytes52("0x" + "aa" * 52),
                attestation_private_key_file="att.ssz",
                proposal_private_key_file="prop.ssz",
            )

    def test_wrong_length_public_key_rejected(self) -> None:
        """Hex strings that don't decode to exactly 52 bytes are rejected."""
        with pytest.raises((SSZValueError, ValidationError)):
            ValidatorManifestEntry(
                index=ValidatorIndex(0),
                attestation_public_key_hex=Bytes52("0x" + "aa" * 10),
                proposal_public_key_hex=Bytes52("0x" + "bb" * 52),
                attestation_private_key_file="att.ssz",
                proposal_private_key_file="prop.ssz",
            )


class TestValidatorManifest:
    """Tests for ValidatorManifest Pydantic model and YAML loading."""

    def test_from_yaml_file_loads_metadata(self, tmp_path: Path) -> None:
        """All top-level metadata fields are parsed correctly."""
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(yaml.dump(_minimal_manifest_dict()))

        manifest = ValidatorManifest.from_yaml_file(manifest_file)

        assert manifest == ValidatorManifest(
            key_scheme="SIGTopLevelTargetSumLifetime32Dim64Base8",
            hash_function="Poseidon2",
            encoding="TargetSum",
            lifetime=32,
            log_num_active_epochs=5,
            num_active_epochs=32,
            num_validators=0,
            validators=[],
        )

    def test_from_yaml_file_parses_validators_list(self, tmp_path: Path) -> None:
        """Nested validators list is parsed into ValidatorManifestEntry objects."""
        manifest_entry_dicts = [_manifest_entry_dict(0), _manifest_entry_dict(1)]
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(
            yaml.dump(_minimal_manifest_dict(num_validators=2, validators=manifest_entry_dicts))
        )

        manifest = ValidatorManifest.from_yaml_file(manifest_file)

        assert manifest.validators == [
            ValidatorManifestEntry(
                index=ValidatorIndex(0),
                attestation_public_key_hex=Bytes52("0x" + "00" * 52),
                proposal_public_key_hex=Bytes52("0x" + "00" * 52),
                attestation_private_key_file="att_key_0.ssz",
                proposal_private_key_file="prop_key_0.ssz",
            ),
            ValidatorManifestEntry(
                index=ValidatorIndex(1),
                attestation_public_key_hex=Bytes52("0x" + "01" * 52),
                proposal_public_key_hex=Bytes52("0x" + "01" * 52),
                attestation_private_key_file="att_key_1.ssz",
                proposal_private_key_file="prop_key_1.ssz",
            ),
        ]


class TestLoadNodeValidatorMapping:
    """Tests for loading node-to-validator index mapping from YAML."""

    def test_normal_loading_multiple_nodes(self, tmp_path: Path) -> None:
        """Multiple node entries are loaded into the correct structure."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0, 1], "node_1": [2, 3], "node_2": [4]}))

        mapping = load_node_validator_mapping(validators_file)

        assert mapping == {"node_0": [0, 1], "node_1": [2, 3], "node_2": [4]}

    def test_empty_file_returns_empty_dict(self, tmp_path: Path) -> None:
        """An empty YAML file (parses to None) returns an empty dict."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text("")

        mapping = load_node_validator_mapping(validators_file)

        assert mapping == {}


class TestValidatorRegistry:
    """Tests for ValidatorRegistry dataclass."""

    def _entry(self, km: XmssKeyManager, index: int) -> ValidatorEntry:
        """Create a ValidatorEntry with real keys for the given index."""
        validator_index = ValidatorIndex(index)
        kp = km[validator_index]
        return ValidatorEntry(
            index=validator_index,
            attestation_secret_key=kp.attestation_keypair.secret_key,
            proposal_secret_key=kp.proposal_keypair.secret_key,
        )

    def test_empty_registry_has_no_entries(self) -> None:
        """Newly created registry contains no validators."""
        registry = ValidatorRegistry()

        assert registry_state(registry) == {}
        assert registry.primary_index() is None

    def test_add_single_entry_and_retrieve(self, km: XmssKeyManager) -> None:
        """A single entry is stored and retrievable by index."""
        registry = ValidatorRegistry()
        validator_entry = self._entry(km, 0)
        registry.add(validator_entry)

        assert registry.get(ValidatorIndex(0)) == validator_entry

    def test_get_miss_returns_none(self, km: XmssKeyManager) -> None:
        """get() returns None for an index that was never added."""
        registry = ValidatorRegistry()
        registry.add(self._entry(km, 0))

        assert registry.get(ValidatorIndex(99)) is None

    def test_add_multiple_entries(self, km: XmssKeyManager) -> None:
        """Multiple entries are stored with correct index-to-key mapping."""
        registry = ValidatorRegistry()
        validator_entries = {index: self._entry(km, index) for index in [3, 1, 4]}
        for validator_entry in validator_entries.values():
            registry.add(validator_entry)

        assert registry_state(registry) == {
            ValidatorIndex(1): (
                validator_entries[1].attestation_secret_key,
                validator_entries[1].proposal_secret_key,
            ),
            ValidatorIndex(3): (
                validator_entries[3].attestation_secret_key,
                validator_entries[3].proposal_secret_key,
            ),
            ValidatorIndex(4): (
                validator_entries[4].attestation_secret_key,
                validator_entries[4].proposal_secret_key,
            ),
        }

    def test_contains_known_index(self, km: XmssKeyManager) -> None:
        """__contains__ returns True for a registered validator index."""
        registry = ValidatorRegistry()
        registry.add(self._entry(km, 5))

        assert ValidatorIndex(5) in registry

    def test_contains_unknown_index(self) -> None:
        """__contains__ returns False for an index that was never added."""
        registry = ValidatorRegistry()

        assert ValidatorIndex(99) not in registry

    def test_length_after_adds(self, km: XmssKeyManager) -> None:
        """__len__ reflects the number of entries added."""
        registry = ValidatorRegistry()
        assert len(registry) == 0

        for i in range(4):
            registry.add(self._entry(km, i))

        assert len(registry) == 4

    def test_indices_returns_all_registered_indices(self, km: XmssKeyManager) -> None:
        """All registered indices are returned as a collection."""
        registry = ValidatorRegistry()
        for i in [2, 5, 7]:
            registry.add(self._entry(km, i))

        registered_indices = registry.indices()

        assert set(registered_indices) == {ValidatorIndex(2), ValidatorIndex(5), ValidatorIndex(7)}

    def test_primary_index_empty_registry(self) -> None:
        """Primary index is None for an empty registry."""
        assert ValidatorRegistry().primary_index() is None

    def test_primary_index_single_entry(self, km: XmssKeyManager) -> None:
        """Primary index is the only entry's index."""
        registry = ValidatorRegistry()
        registry.add(self._entry(km, 5))

        assert registry.primary_index() == ValidatorIndex(5)

    def test_primary_index_is_first_inserted(self, km: XmssKeyManager) -> None:
        """Primary index is the first inserted entry (insertion order)."""
        registry = ValidatorRegistry()
        for i in [3, 1, 7]:
            registry.add(self._entry(km, i))

        assert registry.primary_index() == ValidatorIndex(3)

    def test_add_overwrites_existing_entry(self, km: XmssKeyManager) -> None:
        """add() with an existing index replaces the entry, preserving registry size."""
        registry = ValidatorRegistry()
        old_entry = self._entry(km, 5)
        # Create a different entry for the same index using different key pairs.
        kp_attestation = km[ValidatorIndex(6)]
        kp_proposal = km[ValidatorIndex(7)]
        new_entry = ValidatorEntry(
            index=ValidatorIndex(5),
            attestation_secret_key=kp_attestation.attestation_keypair.secret_key,
            proposal_secret_key=kp_proposal.proposal_keypair.secret_key,
        )

        registry.add(old_entry)
        registry.add(new_entry)

        assert len(registry) == 1
        assert registry_state(registry) == {
            ValidatorIndex(5): (
                kp_attestation.attestation_keypair.secret_key,
                kp_proposal.proposal_keypair.secret_key,
            )
        }


def _write_manifest(path: Path, validators: list[dict[str, object]]) -> None:
    """Write a minimal manifest YAML file at path."""
    path.write_text(
        yaml.dump(_minimal_manifest_dict(num_validators=len(validators), validators=validators))
    )


class TestValidatorRegistryFromYaml:
    """Integration tests for the full YAML loading pipeline (files on disk -> registry)."""

    def _write_real_key_files(
        self, km: XmssKeyManager, directory: Path, indices: list[int]
    ) -> None:
        """Write real SSZ-encoded XMSS key files for the given validator indices."""
        for i in indices:
            validator_index = ValidatorIndex(i)
            kp = km[validator_index]
            (directory / f"att_key_{i}.ssz").write_bytes(
                kp.attestation_keypair.secret_key.encode_bytes()
            )
            (directory / f"prop_key_{i}.ssz").write_bytes(
                kp.proposal_keypair.secret_key.encode_bytes()
            )

    def test_happy_path_loads_assigned_validators(self, tmp_path: Path, km: XmssKeyManager) -> None:
        """Registry loads keys only for validators assigned to the specified node."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0, 1], "node_1": [2]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(
            manifest_file,
            [_manifest_entry_dict(0), _manifest_entry_dict(1), _manifest_entry_dict(2)],
        )
        self._write_real_key_files(km, tmp_path, [0, 1])

        registry = ValidatorRegistry.from_yaml(
            node_id="node_0",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert set(registry.indices()) == {ValidatorIndex(0), ValidatorIndex(1)}
        assert len(registry) == 2

        # Loaded keys should match the originals from the key manager.
        for i in [0, 1]:
            validator_index = ValidatorIndex(i)
            validator_entry = registry.get(validator_index)
            assert validator_entry is not None
            expected_attestation = km[validator_index].attestation_keypair.secret_key.encode_bytes()
            expected_proposal = km[validator_index].proposal_keypair.secret_key.encode_bytes()
            assert validator_entry.attestation_secret_key.encode_bytes() == expected_attestation
            assert validator_entry.proposal_secret_key.encode_bytes() == expected_proposal

    def test_unknown_node_returns_empty_registry(self, tmp_path: Path) -> None:
        """An unrecognised node ID produces an empty registry without error."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [])

        registry = ValidatorRegistry.from_yaml(
            node_id="ghost_node",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert registry_state(registry) == {}

    def test_empty_validators_file_returns_empty_registry(self, tmp_path: Path) -> None:
        """An empty validators.yaml produces an empty registry."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text("")

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [])

        registry = ValidatorRegistry.from_yaml(
            node_id="node_0",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert registry_state(registry) == {}

    def test_missing_manifest_entry_logs_warning_and_skips(
        self, tmp_path: Path, km: XmssKeyManager, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Validator indices present in validators.yaml but absent from manifest are skipped."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0, 99]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])
        self._write_real_key_files(km, tmp_path, [0])

        registry = ValidatorRegistry.from_yaml(
            node_id="node_0",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert set(registry.indices()) == {ValidatorIndex(0)}
        assert "99" in caplog.text

    def test_missing_attestation_key_file_raises(self, tmp_path: Path) -> None:
        """Missing attestation SSZ file raises ValueError with a clear message."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])

        with pytest.raises(ValueError) as exception_info:
            ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )
        assert str(exception_info.value) == (
            f"Attestation key file not found: {tmp_path / 'att_key_0.ssz'}"
        )

    def test_missing_proposal_key_file_raises(self, tmp_path: Path, km: XmssKeyManager) -> None:
        """Missing proposal SSZ file raises ValueError after the attestation key loads."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])

        # Write only attestation key, not proposal key.
        kp = km[ValidatorIndex(0)]
        (tmp_path / "att_key_0.ssz").write_bytes(kp.attestation_keypair.secret_key.encode_bytes())

        with pytest.raises(ValueError) as exception_info:
            ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )
        assert str(exception_info.value) == (
            f"Proposal key file not found: {tmp_path / 'prop_key_0.ssz'}"
        )

    def test_corrupt_attestation_key_file_raises(self, tmp_path: Path) -> None:
        """A corrupt attestation SSZ file raises ValueError with a clear message."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])
        (tmp_path / "att_key_0.ssz").write_bytes(b"not valid ssz")
        (tmp_path / "prop_key_0.ssz").write_bytes(b"prop0")

        with pytest.raises(ValueError) as exception_info:
            ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )
        assert str(exception_info.value) == (
            "Failed to load attestation key for validator 0: PRFKey: expected 32 bytes, got 13"
        )

    def test_corrupt_proposal_key_file_raises(self, tmp_path: Path, km: XmssKeyManager) -> None:
        """A corrupt proposal SSZ file raises ValueError after the attestation key loads."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])

        # Write real attestation key but corrupt proposal key.
        kp = km[ValidatorIndex(0)]
        (tmp_path / "att_key_0.ssz").write_bytes(kp.attestation_keypair.secret_key.encode_bytes())
        (tmp_path / "prop_key_0.ssz").write_bytes(b"not valid ssz")

        with pytest.raises(ValueError) as exception_info:
            ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )
        assert str(exception_info.value) == (
            "Failed to load proposal key for validator 0: PRFKey: expected 32 bytes, got 13"
        )

    def test_only_assigned_node_keys_are_loaded(self, tmp_path: Path, km: XmssKeyManager) -> None:
        """Keys for validators belonging to other nodes are never touched."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0], "node_1": [1, 2]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(
            manifest_file,
            [_manifest_entry_dict(0), _manifest_entry_dict(1), _manifest_entry_dict(2)],
        )
        self._write_real_key_files(km, tmp_path, [0])

        registry = ValidatorRegistry.from_yaml(
            node_id="node_0",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert set(registry.indices()) == {ValidatorIndex(0)}
        assert ValidatorIndex(1) not in registry
        assert ValidatorIndex(2) not in registry


class TestValidatorRegistryFromKeysDirectory:
    """Tests for the ream/zeam-layout registry loader."""

    def test_missing_manifest_raises(self, tmp_path: Path) -> None:
        """The loader raises when the manifest file is absent."""
        with pytest.raises(FileNotFoundError) as exception_info:
            ValidatorRegistry.from_keys_directory(node_id="lean_spec_0", base_directory=tmp_path)
        assert str(exception_info.value) == (
            "Validator keys manifest not found: "
            f"{tmp_path / 'hash-sig-keys' / 'validator-keys-manifest.yaml'}"
        )
