import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.types import ValidatorIndex


def test_seeded_key_generation_is_deterministic() -> None:
    manager_a = XmssKeyManager(default_seed=42)
    manager_b = XmssKeyManager(default_seed=42)
    manager_c = XmssKeyManager(default_seed=43)

    pair_a = manager_a.create_and_store_key_pair(ValidatorIndex(0))
    pair_b = manager_b.create_and_store_key_pair(ValidatorIndex(0))
    pair_c = manager_c.create_and_store_key_pair(ValidatorIndex(0))

    assert pair_a.public == pair_b.public
    assert pair_a.secret == pair_b.secret
    assert pair_a.public != pair_c.public
    assert pair_a.secret != pair_c.secret


def test_export_test_vectors_shape_and_metadata() -> None:
    manager = XmssKeyManager(default_seed=7)
    # Explicitly control first key parameters
    manager.create_and_store_key_pair(
        ValidatorIndex(1),
        activation_epoch=5,
        num_active_epochs=10,
        seed=99,
    )
    # Use defaults for second key
    manager.create_and_store_key_pair(ValidatorIndex(2))

    vectors = manager.export_test_vectors(include_private_keys=True)
    assert {entry["validator_index"] for entry in vectors} == {1, 2}

    by_validator = {entry["validator_index"]: entry for entry in vectors}
    first = by_validator[1]
    second = by_validator[2]

    # Public key should be hex-encoded and match the configured length.
    pk_len = manager.scheme.config.PUBLIC_KEY_LEN_BYTES * 2
    assert len(first["public_key"]) == pk_len
    assert len(second["public_key"]) == pk_len

    # Metadata should reflect the parameters used to create the keys.
    assert first["activation_epoch"] == 5
    assert first["num_active_epochs"] == 10
    assert first["seed"] == 99

    assert second["activation_epoch"] == manager.default_activation_epoch
    assert second["num_active_epochs"] == manager.default_num_active_epochs
    assert second["seed"] == manager.default_seed

    # Secret key is only present when requested.
    assert "secret_key" in first
    assert isinstance(first["secret_key"], dict)
    assert "secret_key" in second
