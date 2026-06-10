"""Behaviour tests for the XMSS containers."""

import json

import pytest
from pydantic import ValidationError

from consensus_testing.keys import XmssKeyManager
from lean_spec.spec.crypto.koalabear import P_BYTES
from lean_spec.spec.crypto.xmss.constants import TEST_CONFIG
from lean_spec.spec.crypto.xmss.containers import (
    KeyPair,
    PublicKey,
    SecretKey,
    Signature,
    ValidatorKeyPair,
)
from lean_spec.spec.crypto.xmss.interface import TEST_SIGNATURE_SCHEME
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.ssz import Bytes32, Uint64


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
    """Nested plain-hex mapping accepted as a JSON-load input shape."""
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
    validator_keypair = ValidatorKeyPair(attestation_keypair=keypair_a, proposal_keypair=keypair_b)
    assert validator_keypair.attestation_keypair == keypair_a
    assert validator_keypair.proposal_keypair == keypair_b


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
    keypair_mapping = {
        "attestation_keypair": keypair_a,
        "proposal_keypair": {
            "public_key": keypair_b.public_key.encode_bytes().hex(),
            "secret_key": keypair_b.secret_key.encode_bytes().hex(),
        },
    }
    validator_keypair = ValidatorKeyPair.model_validate(keypair_mapping)
    assert validator_keypair.attestation_keypair == keypair_a
    assert validator_keypair.proposal_keypair == keypair_b


def test_json_dump_emits_nested_hex_shape(keypair_a: KeyPair, keypair_b: KeyPair) -> None:
    """JSON dump emits each key half as a 0x-prefixed hex string."""
    validator_keypair = ValidatorKeyPair(attestation_keypair=keypair_a, proposal_keypair=keypair_b)
    assert json.loads(validator_keypair.model_dump_json()) == {
        "attestation_keypair": {
            "public_key": "0x" + keypair_a.public_key.encode_bytes().hex(),
            "secret_key": "0x" + keypair_a.secret_key.encode_bytes().hex(),
        },
        "proposal_keypair": {
            "public_key": "0x" + keypair_b.public_key.encode_bytes().hex(),
            "secret_key": "0x" + keypair_b.secret_key.encode_bytes().hex(),
        },
    }


def test_json_roundtrip_preserves_equality(keypair_a: KeyPair, keypair_b: KeyPair) -> None:
    """Dump-then-validate yields a model equal to the original."""
    # Invariant: encode then decode is identity on every ValidatorKeyPair.
    validator_keypair = ValidatorKeyPair(attestation_keypair=keypair_a, proposal_keypair=keypair_b)
    assert (
        ValidatorKeyPair.model_validate_json(validator_keypair.model_dump_json())
        == validator_keypair
    )


def test_frozen_blocks_field_assignment(keypair_a: KeyPair, keypair_b: KeyPair) -> None:
    """Reassigning a field after construction raises (frozen model)."""
    validator_keypair = ValidatorKeyPair(attestation_keypair=keypair_a, proposal_keypair=keypair_b)
    with pytest.raises(ValidationError):
        validator_keypair.attestation_keypair = keypair_b


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
    keypair_mapping = {
        "attestation_keypair": bad_value,
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(keypair_mapping)


def test_rejects_missing_public_key(
    keypair_a: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """A role mapping without the public half fails to decode."""
    # KeyError on value["public_key"] surfaces as ValidationError.
    keypair_mapping = {
        "attestation_keypair": {"secret_key": keypair_a.secret_key.encode_bytes().hex()},
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(keypair_mapping)


def test_rejects_missing_secret_key(
    keypair_a: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """A role mapping without the secret half fails to decode."""
    # KeyError on value["secret_key"] surfaces as ValidationError.
    keypair_mapping = {
        "attestation_keypair": {"public_key": keypair_a.public_key.encode_bytes().hex()},
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(keypair_mapping)


def test_rejects_non_string_hex_value(
    keypair_a: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """Hex fields must be strings; an integer is rejected before SSZ decoding."""
    # AttributeError on int.removeprefix surfaces as ValidationError.
    keypair_mapping = {
        "attestation_keypair": {
            "public_key": 12345,
            "secret_key": keypair_a.secret_key.encode_bytes().hex(),
        },
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(keypair_mapping)


def test_rejects_invalid_hex_characters(
    keypair_a: KeyPair, hex_dict: dict[str, dict[str, str]]
) -> None:
    """Non-hex characters surface as a validation error from the SSZ codec."""
    # ValueError from bytes.fromhex is wrapped natively by Pydantic.
    keypair_mapping = {
        "attestation_keypair": {
            "public_key": "zz" * 26,
            "secret_key": keypair_a.secret_key.encode_bytes().hex(),
        },
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(keypair_mapping)


def test_rejects_wrong_length_hex(keypair_a: KeyPair, hex_dict: dict[str, dict[str, str]]) -> None:
    """A hex string of the wrong byte length fails SSZ deserialization."""
    # SSZError from decode_bytes is rerouted to ValueError by the validator.
    keypair_mapping = {
        "attestation_keypair": {
            "public_key": "deadbeef",
            "secret_key": keypair_a.secret_key.encode_bytes().hex(),
        },
        "proposal_keypair": hex_dict["proposal_keypair"],
    }
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate(keypair_mapping)


def test_rejects_missing_role(hex_dict: dict[str, dict[str, str]]) -> None:
    """Both attestation and proposal roles are required."""
    with pytest.raises(ValidationError):
        ValidatorKeyPair.model_validate({"attestation_keypair": hex_dict["attestation_keypair"]})


def test_keypair_frozen(keypair_a: KeyPair) -> None:
    """KeyPair fields cannot be reassigned (StrictBaseModel is frozen)."""
    with pytest.raises(ValidationError):
        keypair_a.public_key = keypair_a.public_key


def test_keypair_decodes_public_and_secret_hex(keypair_a: KeyPair) -> None:
    """A key pair validates from hex strings for both halves."""
    decoded = KeyPair.model_validate(
        {
            "public_key": keypair_a.public_key.encode_bytes().hex(),
            "secret_key": keypair_a.secret_key.encode_bytes().hex(),
        }
    )
    assert decoded == keypair_a


def test_keypair_rejects_invalid_public_key_hex(keypair_a: KeyPair) -> None:
    """A malformed public-key hex string surfaces as a validation error."""
    with pytest.raises(
        ValidationError,
        match=r"(?s)^1 validation error for KeyPair\npublic_key\n"
        r"  Value error, invalid PublicKey hex: "
        r"Value 4022250974 exceeds field modulus 2130706433 .*\Z",
    ):
        KeyPair.model_validate(
            {
                "public_key": "deadbeef",
                "secret_key": keypair_a.secret_key.encode_bytes().hex(),
            }
        )


def test_keypair_rejects_invalid_secret_key_hex(keypair_a: KeyPair) -> None:
    """A malformed secret-key hex string surfaces as a validation error."""
    with pytest.raises(
        ValidationError,
        match=r"(?s)^1 validation error for KeyPair\nsecret_key\n"
        r"  Value error, invalid SecretKey hex: PRFKey: expected 32 bytes, got 4 .*\Z",
    ):
        KeyPair.model_validate(
            {
                "public_key": keypair_a.public_key.encode_bytes().hex(),
                "secret_key": "deadbeef",
            }
        )


@pytest.fixture(scope="module")
def signed_key_pair() -> KeyPair:
    """A key pair generated directly from the test scheme."""
    return TEST_SIGNATURE_SCHEME.key_gen(Slot(0), Uint64(32))


@pytest.fixture(scope="module")
def sample_signature(signed_key_pair: KeyPair) -> Signature:
    """A signature over a fixed message at slot zero."""
    return TEST_SIGNATURE_SCHEME.sign(
        signed_key_pair.secret_key, Slot(0), Bytes32(bytes([42] * 32))
    )


def test_public_key_ssz_roundtrip(signed_key_pair: KeyPair) -> None:
    """A public key encodes and decodes back to an equal value."""
    public_key = signed_key_pair.public_key
    assert PublicKey.decode_bytes(public_key.encode_bytes()) == public_key


def test_public_key_encoded_size_matches_layout(signed_key_pair: KeyPair) -> None:
    """The encoded public key is the digest plus parameter packed into field bytes."""
    encoded = signed_key_pair.public_key.encode_bytes()
    expected_encoded_length = (
        TEST_CONFIG.HASH_LENGTH_FIELD_ELEMENTS + TEST_CONFIG.PARAMETER_LENGTH
    ) * P_BYTES
    assert len(encoded) == expected_encoded_length


def test_secret_key_ssz_roundtrip(signed_key_pair: KeyPair) -> None:
    """A secret key encodes and decodes back to an equal value."""
    secret_key = signed_key_pair.secret_key
    assert SecretKey.decode_bytes(secret_key.encode_bytes()) == secret_key


def test_signature_is_fixed_size() -> None:
    """A signature reports as fixed-size on the wire."""
    assert Signature.is_fixed_size() is True


def test_signature_byte_length_matches_config() -> None:
    """The signature byte length matches the configured fixed length."""
    assert Signature.get_byte_length() == TEST_CONFIG.SIGNATURE_LENGTH_BYTES


def test_signature_ssz_roundtrip(sample_signature: Signature) -> None:
    """A signature encodes and decodes back to an equal value."""
    assert Signature.decode_bytes(sample_signature.encode_bytes()) == sample_signature


def test_signature_encoded_size_matches_config(sample_signature: Signature) -> None:
    """The encoded signature length matches the advertised fixed length."""
    assert len(sample_signature.encode_bytes()) == TEST_CONFIG.SIGNATURE_LENGTH_BYTES


def test_signature_json_is_prefixed_hex(sample_signature: Signature) -> None:
    """The JSON form is a hex string prefixed with the byte marker."""
    dumped = json.loads(sample_signature.model_dump_json())
    assert dumped == "0x" + sample_signature.encode_bytes().hex()


def test_signature_decodes_from_json(sample_signature: Signature) -> None:
    """A signature decodes back from its JSON hex form."""
    encoded = "0x" + sample_signature.encode_bytes().hex()
    assert Signature.from_hex(encoded) == sample_signature
