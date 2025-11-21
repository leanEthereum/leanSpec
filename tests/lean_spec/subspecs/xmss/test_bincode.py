"""Tests for bincode serialization compatibility with Rust."""

from typing import Any

import pytest

from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.koalabear.field import P
from lean_spec.subspecs.xmss.bincode import (
    decode_varint_u64,
    deserialize_vec,
    encode_varint_u64,
    serialize_vec,
)
from lean_spec.subspecs.xmss.constants import XmssConfig
from lean_spec.subspecs.xmss.containers import PublicKey

# Specific configuration to test bincode
XMSS_CONFIG = XmssConfig(
    MESSAGE_LENGTH=32,
    LOG_LIFETIME=6,
    DIMENSION=7,
    BASE=2,
    FINAL_LAYER=3,
    TARGET_SUM=7,
    MAX_TRIES=1_000,
    PARAMETER_LEN=5,
    TWEAK_LEN_FE=2,
    MSG_LEN_FE=18,
    RAND_LEN_FE=11,
    HASH_LEN_FE=7,
    CAPACITY=9,
    POS_OUTPUT_LEN_PER_INV_FE=15,
    POS_INVOCATIONS=1,
)


class TestVarintEncoding:
    """Test varint encoding/decoding against Rust bincode reference implementation."""

    # Format: (value, expected_hex_bytes)
    ENCODING_TEST_CASES = [
        # Path 1: value < 251 (single byte)
        (0, "00"),
        (1, "01"),
        (100, "64"),
        (250, "fa"),
        # Path 2: 251 <= value < 2^16 (marker 251 + u16 little-endian)
        (251, "fb fb 00"),
        (252, "fb fc 00"),
        (1000, "fb e8 03"),
        (65535, "fb ff ff"),  # 2^16 - 1
        # Path 3: 2^16 <= value < 2^32 (marker 252 + u32 little-endian)
        (65536, "fc 00 00 01 00"),  # 2^16
        (100000, "fc a0 86 01 00"),
        (27304679, "fc e7 a2 a0 01"),  # Example from deserialization tests
        (2695030780, "fc fc e7 a2 a0"),  # The problematic value we encountered
        (4294967295, "fc ff ff ff ff"),  # 2^32 - 1
        # Path 4: value >= 2^32 (marker 253 + u64 little-endian)
        (4294967296, "fd 00 00 00 00 01 00 00 00"),  # 2^32
        (1000000000000, "fd 00 10 a5 d4 e8 00 00 00"),  # 1 trillion
        (18446744073709551615, "fd ff ff ff ff ff ff ff ff"),  # 2^64 - 1 (max u64)
    ]

    @pytest.mark.parametrize("value,expected_hex", ENCODING_TEST_CASES)
    def test_encode_varint_u64(self, value: int, expected_hex: str) -> None:
        """Test that encode_varint_u64 produces the same output as Rust bincode."""
        result = encode_varint_u64(value)
        expected = bytes.fromhex(expected_hex.replace(" ", ""))
        assert result == expected, (
            f"Encoding mismatch for value {value} (0x{value:016x}):\n"
            f"  Expected: {expected.hex()}\n"
            f"  Got:      {result.hex()}"
        )

    @pytest.mark.parametrize("value,expected_hex", ENCODING_TEST_CASES)
    def test_decode_varint_u64(self, value: int, expected_hex: str) -> None:
        """Test that decode_varint_u64 correctly decodes Rust bincode output."""
        encoded = bytes.fromhex(expected_hex.replace(" ", ""))
        decoded_value, bytes_consumed = decode_varint_u64(encoded, 0)
        assert decoded_value == value, (
            f"Decoding mismatch for bytes {expected_hex}:\n"
            f"  Expected: {value}\n"
            f"  Got:      {decoded_value}"
        )
        assert bytes_consumed == len(encoded), (
            f"Wrong number of bytes consumed for {expected_hex}:\n"
            f"  Expected: {len(encoded)}\n"
            f"  Got:      {bytes_consumed}"
        )

    @pytest.mark.parametrize("value,expected_hex", ENCODING_TEST_CASES)
    def test_roundtrip(self, value: int, expected_hex: str) -> None:
        """Test encode -> decode roundtrip."""
        encoded = encode_varint_u64(value)
        decoded_value, _ = decode_varint_u64(encoded, 0)
        assert decoded_value == value

    def test_encode_negative_value_raises(self) -> None:
        """Test that encoding negative values raises ValueError."""
        with pytest.raises(ValueError, match="Cannot encode negative value"):
            encode_varint_u64(-1)

    def test_encode_too_large_value_raises(self) -> None:
        """Test that encoding values >= 2^64 raises ValueError."""
        with pytest.raises(ValueError, match="Value too large for u64 varint"):
            encode_varint_u64(2**64)

    def test_decode_insufficient_data_raises(self) -> None:
        """Test that decoding with insufficient data raises ValueError."""
        # Marker 251 indicates u16, but only provide 1 more byte
        with pytest.raises(ValueError, match="Not enough data for u16 varint"):
            decode_varint_u64(bytes([251, 0]), 0)

        # Marker 252 indicates u32, but only provide 1 more byte
        with pytest.raises(ValueError, match="Not enough data for u32 varint"):
            decode_varint_u64(bytes([252, 0]), 0)

        # Marker 253 indicates u64, but only provide 1 more byte
        with pytest.raises(ValueError, match="Not enough data for u64 varint"):
            decode_varint_u64(bytes([253, 0]), 0)

    def test_decode_empty_data_raises(self) -> None:
        """Test that decoding empty data raises ValueError."""
        with pytest.raises(ValueError, match="Not enough data to decode varint"):
            decode_varint_u64(b"", 0)

    def test_decode_with_offset(self) -> None:
        """Test decoding with a non-zero offset."""
        # Encode three values and concatenate
        data = encode_varint_u64(100) + encode_varint_u64(1000) + encode_varint_u64(100000)

        # Decode first value
        val1, consumed1 = decode_varint_u64(data, 0)
        assert val1 == 100
        assert consumed1 == 1

        # Decode second value
        val2, consumed2 = decode_varint_u64(data, consumed1)
        assert val2 == 1000
        assert consumed2 == 3

        # Decode third value
        val3, consumed3 = decode_varint_u64(data, consumed1 + consumed2)
        assert val3 == 100000
        assert consumed3 == 5


class TestFieldElementVarintEncoding:
    """Test field element varint encoding against Rust reference implementation."""

    # Test cases from Rust test_field_element_varint_encoding
    # Format: (field_value, expected_hex_bytes)
    FIELD_ENCODING_TEST_CASES = [
        (0, "00"),
        (1, "01"),
        (250, "fa"),
        (251, "fb fb 00"),
        (65535, "fb ff ff"),
        (65536, "fc 00 00 01 00"),
        (27304679, "fc e7 a2 a0 01"),
        (2130706432, "fc 00 00 00 7f"),  # p - 1 for Koalabear
    ]

    @pytest.mark.parametrize("field_value,expected_hex", FIELD_ENCODING_TEST_CASES)
    def test_field_element_encode(self, field_value: int, expected_hex: str) -> None:
        """Test that field elements encode the same as Rust."""
        fp = Fp(value=field_value)
        result = encode_varint_u64(fp.value)
        expected = bytes.fromhex(expected_hex.replace(" ", ""))
        assert result == expected, (
            f"Field element encoding mismatch for Fp({field_value}):\n"
            f"  Expected: {expected.hex()}\n"
            f"  Got:      {result.hex()}"
        )

    @pytest.mark.parametrize("field_value,expected_hex", FIELD_ENCODING_TEST_CASES)
    def test_field_element_decode(self, field_value: int, expected_hex: str) -> None:
        """Test that field elements decode the same as Rust."""
        encoded = bytes.fromhex(expected_hex.replace(" ", ""))
        decoded_value, bytes_consumed = decode_varint_u64(encoded, 0)
        fp = Fp(value=decoded_value)
        assert fp.value == field_value, (
            f"Field element decoding mismatch for bytes {expected_hex}:\n"
            f"  Expected: Fp({field_value})\n"
            f"  Got:      Fp({fp.value})"
        )
        assert bytes_consumed == len(encoded)


class TestBoundaryConditions:
    """Test encoding/decoding at exact boundary values."""

    def test_boundary_250_251(self) -> None:
        """Test the boundary between single byte and marker 251 encoding."""
        # 250 should be single byte
        assert encode_varint_u64(250) == bytes([250])
        # 251 should be marker + u16
        assert encode_varint_u64(251) == bytes([251, 251, 0])

    def test_boundary_65535_65536(self) -> None:
        """Test the boundary between u16 and u32 encoding."""
        # 65535 (2^16 - 1) should be marker 251 + u16
        assert encode_varint_u64(65535) == bytes([251, 255, 255])
        # 65536 (2^16) should be marker 252 + u32
        assert encode_varint_u64(65536) == bytes([252, 0, 0, 1, 0])

    def test_boundary_4294967295_4294967296(self) -> None:
        """Test the boundary between u32 and u64 encoding."""
        # 4294967295 (2^32 - 1) should be marker 252 + u32
        assert encode_varint_u64(4294967295) == bytes([252, 255, 255, 255, 255])
        # 4294967296 (2^32) should be marker 253 + u64
        assert encode_varint_u64(4294967296) == bytes([253, 0, 0, 0, 0, 1, 0, 0, 0])


class TestKoalabearFieldModulus:
    """Test that field element values are within the Koalabear field modulus."""

    def test_field_modulus(self) -> None:
        """Verify that the Koalabear field modulus is 2^31 - 2^24 + 1 = 2130706433."""
        assert P == 2130706433

    def test_max_field_value(self) -> None:
        """Test encoding the maximum valid field element (p - 1)."""
        max_field_value = P - 1  # 2130706432
        fp = Fp(value=max_field_value)
        encoded = encode_varint_u64(fp.value)
        expected = bytes.fromhex("fc 00 00 00 7f".replace(" ", ""))
        assert encoded == expected

    def test_value_exceeding_modulus_wraps(self) -> None:
        """Test that creating Fp with value >= modulus wraps (modulo reduction)."""
        fp_at_modulus = Fp(value=P)
        assert fp_at_modulus.value == 0

        fp_large = Fp(value=2695030780)
        expected_wrapped = 2695030780 % P
        assert fp_large.value == expected_wrapped


class TestVecSerialization:
    """Test serialize_vec and deserialize_vec against Rust bincode reference.

    Reference Rust test: test_vec_serialization in leanSig/src/lib.rs
    """

    def test_empty_vec(self) -> None:
        """Test serializing an empty vector."""
        result = serialize_vec([], encode_varint_u64)
        expected = bytes.fromhex("00")
        assert result == expected

    def test_single_element_vec(self) -> None:
        """Test serializing a vector with one element."""
        result = serialize_vec([42], encode_varint_u64)
        expected = bytes.fromhex("01 2a")
        assert result == expected

    def test_small_vec(self) -> None:
        """Test serializing a small vector with 3 elements."""
        result = serialize_vec([1, 100, 1000], encode_varint_u64)
        expected = bytes.fromhex("03 01 64 fb e8 03")
        assert result == expected

    def test_boundary_values_vec(self) -> None:
        """Test vector with values crossing encoding boundaries."""
        result = serialize_vec([250, 251, 65536, 4294967296], encode_varint_u64)
        expected = bytes.fromhex("04 fa fb fb 00 fc 00 00 01 00 fd 00 00 00 00 01 00 00 00")
        assert result == expected

    def test_deserialize_empty_vec(self) -> None:
        """Test deserializing an empty vector."""
        data = bytes.fromhex("00")
        result, consumed = deserialize_vec(data, 0, decode_varint_u64)
        assert result == []
        assert consumed == 1

    def test_deserialize_single_element_vec(self) -> None:
        """Test deserializing a vector with one element."""
        from lean_spec.subspecs.xmss.bincode import deserialize_vec

        data = bytes.fromhex("01 2a")
        result, consumed = deserialize_vec(data, 0, decode_varint_u64)
        assert result == [42]
        assert consumed == 2

    def test_deserialize_small_vec(self) -> None:
        """Test deserializing a small vector."""
        from lean_spec.subspecs.xmss.bincode import deserialize_vec

        data = bytes.fromhex("03 01 64 fb e8 03")
        result, consumed = deserialize_vec(data, 0, decode_varint_u64)
        assert result == [1, 100, 1000]
        assert consumed == 6

    def test_deserialize_boundary_values_vec(self) -> None:
        """Test deserializing vector with boundary values."""
        from lean_spec.subspecs.xmss.bincode import deserialize_vec

        data = bytes.fromhex("04 fa fb fb 00 fc 00 00 01 00 fd 00 00 00 00 01 00 00 00")
        result, consumed = deserialize_vec(data, 0, decode_varint_u64)
        assert result == [250, 251, 65536, 4294967296]
        assert consumed == 19

    def test_vec_roundtrip(self) -> None:
        """Test serialize -> deserialize roundtrip."""
        from lean_spec.subspecs.xmss.bincode import deserialize_vec, serialize_vec

        original = [1, 100, 1000, 65536, 4294967296]
        serialized = serialize_vec(original, encode_varint_u64)
        deserialized, _ = deserialize_vec(serialized, 0, decode_varint_u64)
        assert deserialized == original

    def test_deserialize_with_offset(self) -> None:
        """Test deserializing from a non-zero offset."""
        from lean_spec.subspecs.xmss.bincode import deserialize_vec, serialize_vec

        vec1_data = serialize_vec([42], encode_varint_u64)
        vec2_data = serialize_vec([1, 2, 3], encode_varint_u64)
        combined_data = vec1_data + vec2_data

        result1, consumed1 = deserialize_vec(combined_data, 0, decode_varint_u64)
        assert result1 == [42]

        result2, consumed2 = deserialize_vec(combined_data, consumed1, decode_varint_u64)
        assert result2 == [1, 2, 3]
        assert consumed1 + consumed2 == len(combined_data)


class TestPublicKeySerialization:
    """Test PublicKey serialization/deserialization against Rust bincode reference."""

    # Test data from Rust with seed, hex bytes, and expected field element values
    PUBLIC_KEY_TEST_CASES = [
        # Seed 42
        {
            "seed": 42,
            "hex": (
                "fc165f210bfc305d7700fc16db4f74fc92015e3dfcb85aab0ffcbb2afa59fc"
                "cfc18a1bfc6a4ad80efc64484145fc4a82f210fc81759218fc67db4214"
            ),
            "root": [
                Fp(value=186736406),
                Fp(value=7822640),
                Fp(value=1951390486),
                Fp(value=1029570962),
                Fp(value=262888120),
                Fp(value=1509567163),
                Fp(value=462078415),
            ],
            "parameter": [
                Fp(value=249055850),
                Fp(value=1161906276),
                Fp(value=284328522),
                Fp(value=412251521),
                Fp(value=339925863),
            ],
        },
        # Seed 123
        {
            "seed": 123,
            "hex": (
                "fce2a1d26efc3012f03efcdb77bd08fc68f03105fcba14f12ffc66dc5805fc"
                "39cb8621fc9a390146fc90924a0ffc821fba64fced44626efc1c0a8079"
            ),
            "root": [
                Fp(value=1859297762),
                Fp(value=1055920688),
                Fp(value=146634715),
                Fp(value=87158888),
                Fp(value=804328634),
                Fp(value=89709670),
                Fp(value=562481977),
            ],
            "parameter": [
                Fp(value=1174485402),
                Fp(value=256545424),
                Fp(value=1689919362),
                Fp(value=1851933933),
                Fp(value=2038434332),
            ],
        },
        # Seed 999
        {
            "seed": 999,
            "hex": (
                "fc098fc066fc8180e66dfc9ac3367afc8b4eb212fcb7589e35fc045e4f7cfc"
                "56d01d5afc7020427cfc82a19a0bfc749f1009fc37ed571efc6da8ef1e"
            ),
            "root": [
                Fp(value=1723895561),
                Fp(value=1843822721),
                Fp(value=2050409370),
                Fp(value=313675403),
                Fp(value=899569847),
                Fp(value=2085576196),
                Fp(value=1511903318),
            ],
            "parameter": [
                Fp(value=2084708464),
                Fp(value=194683266),
                Fp(value=152084340),
                Fp(value=509078839),
                Fp(value=519022701),
            ],
        },
        # Seed 12345
        {
            "seed": 12345,
            "hex": (
                "fcae1ed857fc58427c52fce4f0e941fcb6ce2e15fcb9ce0d65fcc13aad4ffc"
                "c395c63cfc94bad747fcc1c3a522fc198c0b71fc8812bb1ffcf72acd7b"
            ),
            "root": [
                Fp(value=1473781422),
                Fp(value=1383875160),
                Fp(value=1105850596),
                Fp(value=355389110),
                Fp(value=1695403705),
                Fp(value=1336752833),
                Fp(value=1019647427),
            ],
            "parameter": [
                Fp(value=1205320340),
                Fp(value=581288897),
                Fp(value=1896582169),
                Fp(value=532353672),
                Fp(value=2077043447),
            ],
        },
    ]

    @pytest.mark.parametrize("test_case", PUBLIC_KEY_TEST_CASES)
    def test_deserialize_public_key(self, test_case: dict[str, Any]) -> None:
        """Test deserializing public keys from Rust bincode output."""

        data = bytes.fromhex(test_case["hex"])
        pk = PublicKey.from_bincode_bytes(data, XMSS_CONFIG)

        # Verify root field elements - compare Fp objects directly
        assert len(pk.root) == len(test_case["root"]), (
            f"Root length mismatch for seed {test_case['seed']}"
        )
        for i, expected in enumerate(test_case["root"]):
            assert pk.root[i] == expected, (
                f"Root[{i}] mismatch for seed {test_case['seed']}: "
                f"expected {expected}, got {pk.root[i]}"
            )

        # Verify parameter field elements - compare Fp objects directly
        assert len(pk.parameter) == len(test_case["parameter"]), (
            f"Parameter length mismatch for seed {test_case['seed']}"
        )
        for i, expected in enumerate(test_case["parameter"]):
            assert pk.parameter[i] == expected, (
                f"Parameter[{i}] mismatch for seed {test_case['seed']}: "
                f"expected {expected}, got {pk.parameter[i]}"
            )

    @pytest.mark.parametrize("test_case", PUBLIC_KEY_TEST_CASES)
    def test_serialize_public_key(self, test_case: dict[str, Any]) -> None:
        """Test serializing public keys to match Rust bincode output."""

        # Create PublicKey from expected Fp values
        pk = PublicKey(
            root=test_case["root"],
            parameter=test_case["parameter"],
        )

        result = pk.to_bincode_bytes(XMSS_CONFIG)
        expected = bytes.fromhex(test_case["hex"])

        assert result == expected, (
            f"Serialization mismatch for seed {test_case['seed']}:\n"
            f"  Expected: {expected.hex()}\n"
            f"  Got:      {result.hex()}"
        )

    @pytest.mark.parametrize("test_case", PUBLIC_KEY_TEST_CASES)
    def test_public_key_roundtrip(self, test_case: dict[str, Any]) -> None:
        """Test serialize -> deserialize roundtrip for public keys."""

        # Deserialize from Rust data
        data = bytes.fromhex(test_case["hex"])
        pk1 = PublicKey.from_bincode_bytes(data, XMSS_CONFIG)

        # Serialize back
        serialized = pk1.to_bincode_bytes(XMSS_CONFIG)

        # Deserialize again
        pk2 = PublicKey.from_bincode_bytes(serialized, XMSS_CONFIG)

        # Verify fields match - compare Fp objects directly
        assert len(pk1.root) == len(pk2.root)
        for i in range(len(pk1.root)):
            assert pk1.root[i] == pk2.root[i]

        assert len(pk1.parameter) == len(pk2.parameter)
        for i in range(len(pk1.parameter)):
            assert pk1.parameter[i] == pk2.parameter[i]

    def test_public_key_length_validation(self) -> None:
        """Test that public keys validate their field lengths."""

        # Valid public key from test case
        test_case = self.PUBLIC_KEY_TEST_CASES[0]
        pk = PublicKey(
            root=test_case["root"],
            parameter=test_case["parameter"],
        )

        # Should serialize successfully with correct config
        serialized = pk.to_bincode_bytes(XMSS_CONFIG)
        assert len(serialized) == 60  # Known length from Rust tests

        # Invalid: wrong root length
        pk_bad_root = PublicKey(
            root=[Fp(value=0)] * 5,  # Wrong length
            parameter=test_case["parameter"],
        )
        with pytest.raises(ValueError, match="Invalid root length"):
            pk_bad_root.to_bincode_bytes(XMSS_CONFIG)

        # Invalid: wrong parameter length
        pk_bad_param = PublicKey(
            root=test_case["root"],
            parameter=[Fp(value=0)] * 3,  # Wrong length
        )
        with pytest.raises(ValueError, match="Invalid parameter length"):
            pk_bad_param.to_bincode_bytes(XMSS_CONFIG)
