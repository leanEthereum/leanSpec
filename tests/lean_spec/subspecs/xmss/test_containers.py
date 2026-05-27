"""Behaviour tests for ValidatorKeyPair."""

import json

import pytest
from consensus_testing.keys import XmssKeyManager
from pydantic import ValidationError

from lean_spec.subspecs.xmss.containers import KeyPair, ValidatorKeyPair
from lean_spec.types import ValidatorIndex


@pytest.fixture(scope="module")
def keypair_a() -> KeyPair:
    """Real KeyPair drawn from validator zero's attestation role."""
    return XmssKeyManager.shared()[ValidatorIndex(0)].attestation_keypair


@pytest.fixture(scope="module")
def keypair_b() -> KeyPair:
    """Second real KeyPair, distinct from keypair_a (validator zero's proposal role)."""
    return XmssKeyManager.shared()[ValidatorIndex(0)].proposal_keypair


@pytest.fixture(scope="module")
def hex_dict(keypair_a: KeyPair, keypair_b: KeyPair) -> dict[str, dict[str, str]]:
    """Nested-hex JSON mapping that mirrors the on-disk format."""
    return {
        "attestation_keypair": {
            "public_key": keypair_a.public_key.encode_bytes().hex(),
            "secret_key": keypair_a.secret_key.encode_bytes().hex(),
        },
        "proposal_keypair": {
            "public_key": keypair_b.public_key.encode_bytes().hex(),
            "secret_key": keypair_b.secret_key.encode_bytes().hex(),
        },
    }


def test_construct_from_keypair_instances(keypair_a: KeyPair, keypair_b: KeyPair) -> None:
    """Direct construction stores both pairs by value."""
    # Passing KeyPair instances skips the hex-decode branch.
    vkp = ValidatorKeyPair(attestation_keypair=keypair_a, proposal_keypair=keypair_b)
    assert vkp.attestation_keypair == keypair_a
    assert vkp.proposal_keypair == keypair_b


def test_validate_from_nested_hex_dict(
    keypair_a: KeyPair, keypair_b: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """A nested hex mapping is the supported JSON-load shape."""
    assert ValidatorKeyPair.model_validate(hex_dict) == ValidatorKeyPair(
        attestation_keypair=keypair_a, proposal_keypair=keypair_b
    )


def test_validator_accepts_0x_prefix(
    keypair_a: KeyPair, keypair_b: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """Hex blobs with a leading "0x" decode identically to plain hex."""
    # Prefix only the attestation half; both must decode to the same instance.
    prefixed = {
        "attestation_keypair": {
            "public_key": "0x" + hex_dict["attestation_keypair"]["public_key"],
            "secret_key": "0x" + hex_dict["attestation_keypair"]["secret_key"],
        },
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    assert ValidatorKeyPair.model_validate(prefixed) == ValidatorKeyPair(
        attestation_keypair=keypair_a, proposal_keypair=keypair_b
    )


def test_validator_accepts_mixed_inputs(keypair_a: KeyPair, keypair_b: KeyPair) -> None:
    """One role as a KeyPair instance, the other as a hex mapping, both decode."""
    data = {
        "attestation_keypair": keypair_a,
        "proposal_keypair": {
            "public_key": keypair_b.public_key.encode_bytes().hex(),
            "secret_key": keypair_b.secret_key.encode_bytes().hex(),
        },
    }
    vkp = ValidatorKeyPair.model_validate(data)
    assert vkp.attestation_keypair == keypair_a
    assert vkp.proposal_keypair == keypair_b


def test_json_dump_emits_nested_hex_shape(
    keypair_a: KeyPair, keypair_b: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """JSON dump produces the on-disk nested-hex layout."""
    vkp = ValidatorKeyPair(attestation_keypair=keypair_a, proposal_keypair=keypair_b)
    assert json.loads(vkp.model_dump_json()) == hex_dict


def test_json_roundtrip_preserves_equality(keypair_a: KeyPair, keypair_b: KeyPair) -> None:
    """Dump-then-validate yields a model equal to the original."""
    # Invariant: encode then decode is identity on every ValidatorKeyPair.
    vkp = ValidatorKeyPair(attestation_keypair=keypair_a, proposal_keypair=keypair_b)
    assert ValidatorKeyPair.model_validate_json(vkp.model_dump_json()) == vkp


def test_frozen_blocks_field_assignment(keypair_a: KeyPair, keypair_b: KeyPair) -> None:
    """Reassigning a field after construction raises (frozen model)."""
    vkp = ValidatorKeyPair(attestation_keypair=keypair_a, proposal_keypair=keypair_b)
    with pytest.raises(ValidationError):
        vkp.attestation_keypair = keypair_b


def test_extra_fields_rejected(
    keypair_a: KeyPair, keypair_b: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """Unknown top-level keys raise so JSON typos fail loud."""
    # A misspelled role name must not silently produce defaults.
    polluted = {**hex_dict, "spurious": "ignored"}
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(polluted)


@pytest.mark.parametrize(
    "bad_value",
    ["plain string", 42, None, ["public_key", "secret_key"], (1, 2)],
)
def test_rejects_non_keypair_non_mapping(
    hex_dict: dict[str, dict[str, str]],
    bad_value: object,
) -> None:
    """Anything that is not a KeyPair or a Mapping fails validation."""
    data = {"attestation_keypair": bad_value, "proposal_keypair": hex_dict["proposal_keypair"]}
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(data)


def test_rejects_missing_public_key(
    keypair_a: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """A role mapping without the public half fails to decode."""
    # KeyError on value["public_key"] surfaces as ValidationError.
    data = {
        "attestation_keypair": {"secret_key": keypair_a.secret_key.encode_bytes().hex()},
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(data)


def test_rejects_missing_secret_key(
    keypair_a: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """A role mapping without the secret half fails to decode."""
    # KeyError on value["secret_key"] surfaces as ValidationError.
    data = {
        "attestation_keypair": {"public_key": keypair_a.public_key.encode_bytes().hex()},
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(data)


def test_rejects_non_string_hex_value(
    keypair_a: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """Hex fields must be strings; an integer is rejected before SSZ decoding."""
    # AttributeError on int.removeprefix surfaces as ValidationError.
    data = {
        "attestation_keypair": {
            "public_key": 12345,
            "secret_key": keypair_a.secret_key.encode_bytes().hex(),
        },
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(data)


def test_rejects_invalid_hex_characters(
    keypair_a: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """Non-hex characters surface as a validation error from the SSZ codec."""
    # ValueError from bytes.fromhex is wrapped natively by Pydantic.
    data = {
        "attestation_keypair": {
            "public_key": "zz" * 26,
            "secret_key": keypair_a.secret_key.encode_bytes().hex(),
        },
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(data)


def test_rejects_wrong_length_hex(keypair_a: KeyPair, hex_dict: dict[str, dict[str, str]]) -> None:
    """A hex string of the wrong byte length fails SSZ deserialization."""
    # SSZError from decode_bytes is rerouted to ValueError by the validator.
    data = {
        "attestation_keypair": {
            "public_key": "deadbeef",
            "secret_key": keypair_a.secret_key.encode_bytes().hex(),
        },
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(data)


def test_rejects_missing_role(hex_dict: dict[str, dict[str, str]]) -> None:
    """Both attestation and proposal roles are required."""
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate({"attestation_keypair": hex_dict["attestation_keypair"]})


def test_keypair_frozen(keypair_a: KeyPair) -> None:
    """KeyPair fields cannot be reassigned (StrictBaseModel is frozen)."""
    with pytest.raises(ValidationError):
        keypair_a.public_key = keypair_a.public_key
