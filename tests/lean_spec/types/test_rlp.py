"""Tests for the RLP (Recursive Length Prefix) encoding module."""

from __future__ import annotations

import pytest

from lean_spec.types.rlp import (
    LONG_LIST_BASE,
    LONG_STRING_BASE,
    SHORT_LIST_MAX_LEN,
    SHORT_LIST_PREFIX,
    SHORT_STRING_MAX_LEN,
    SHORT_STRING_PREFIX,
    SINGLE_BYTE_MAX,
    RLPDecodingError,
    RLPItem,
    decode_rlp,
    decode_rlp_list,
    encode_rlp,
)

# Derived constants for test assertions.
# Long encoding prefixes are BASE + 1 (for 1-byte length).
LONG_STRING_PREFIX = LONG_STRING_BASE + 1  # 0xB8
LONG_LIST_PREFIX = LONG_LIST_BASE + 1  # 0xF8


class TestEncodeEmptyString:
    """Tests for encoding empty byte strings."""

    def test_encode_empty_string(self) -> None:
        """Empty string encodes to 0x80."""
        result = encode_rlp(b"")
        assert result == bytes.fromhex("80")


class TestEncodeSingleByte:
    """Tests for single byte encoding (0x00-0x7f)."""

    def test_encode_byte_0x00(self) -> None:
        """Byte 0x00 encodes as itself."""
        result = encode_rlp(b"\x00")
        assert result == bytes.fromhex("00")

    def test_encode_byte_0x01(self) -> None:
        """Byte 0x01 encodes as itself."""
        result = encode_rlp(b"\x01")
        assert result == bytes.fromhex("01")

    def test_encode_byte_0x7f(self) -> None:
        """Maximum single-byte value (0x7f) encodes as itself."""
        result = encode_rlp(b"\x7f")
        assert result == bytes.fromhex("7f")

    @pytest.mark.parametrize("byte_val", range(0x00, SINGLE_BYTE_MAX + 1))
    def test_encode_all_single_byte_values(self, byte_val: int) -> None:
        """All single-byte values 0x00-0x7f encode as themselves."""
        data = bytes([byte_val])
        result = encode_rlp(data)
        assert result == data


class TestEncodeShortString:
    """Tests for short string encoding (0-55 bytes)."""

    def test_encode_short_string_dog(self) -> None:
        """'dog' encodes with prefix 0x83 (0x80 + 3) followed by ASCII bytes."""
        result = encode_rlp(b"dog")
        assert result == bytes.fromhex("83646f67")

    def test_encode_short_string_55_bytes(self) -> None:
        """55-byte string uses short string encoding (max for this category)."""
        data = b"Lorem ipsum dolor sit amet, consectetur adipisicing eli"
        assert len(data) == SHORT_STRING_MAX_LEN
        result = encode_rlp(data)
        expected = bytes.fromhex(
            "b74c6f72656d20697073756d20646f6c6f722073697420616d65742c20"
            "636f6e7365637465747572206164697069736963696e6720656c69"
        )
        assert result == expected

    def test_encode_single_byte_above_0x7f(self) -> None:
        """Single byte 0x80 uses short string encoding, not single-byte encoding."""
        result = encode_rlp(b"\x80")
        assert result == bytes([SHORT_STRING_PREFIX + 1, 0x80])

    @pytest.mark.parametrize("length", [1, 10, 20, 30, 40, 50, SHORT_STRING_MAX_LEN])
    def test_encode_short_string_various_lengths(self, length: int) -> None:
        """Short strings of various lengths are prefixed with 0x80 + length."""
        # Use bytes above 0x7f to ensure short string encoding is used
        data = bytes([0x80 + (i % 0x7F) for i in range(length)])
        result = encode_rlp(data)
        assert result[0] == SHORT_STRING_PREFIX + length
        assert result[1:] == data


class TestEncodeLongString:
    """Tests for long string encoding (>55 bytes)."""

    def test_encode_long_string_56_bytes(self) -> None:
        """56-byte string uses long string encoding."""
        data = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit"
        assert len(data) == SHORT_STRING_MAX_LEN + 1
        result = encode_rlp(data)
        expected = bytes.fromhex(
            "b8384c6f72656d20697073756d20646f6c6f722073697420616d65742c20"
            "636f6e7365637465747572206164697069736963696e6720656c6974"
        )
        assert result == expected

    def test_encode_long_string_1024_bytes(self) -> None:
        """1024-byte string encodes with 2-byte length prefix."""
        # Use simple repeated bytes to avoid codespell false positives.
        data = b"x" * 1024
        assert len(data) == 1024
        result = encode_rlp(data)
        # Prefix 0xb9 = 0xb7 + 2 (2 bytes for length)
        # Length 0x0400 = 1024 in big-endian
        assert result[0] == LONG_STRING_PREFIX + 1  # 0xb9
        assert result[1:3] == b"\x04\x00"
        assert result[3:] == data

    def test_encode_long_string_boundary(self) -> None:
        """String at exact boundary (56 bytes) uses long encoding."""
        data = b"a" * (SHORT_STRING_MAX_LEN + 1)
        result = encode_rlp(data)
        # Prefix 0xb8 = 0xb7 + 1 (1 byte for length)
        assert result[0] == LONG_STRING_PREFIX
        assert result[1] == len(data)
        assert result[2:] == data


class TestEncodeEmptyList:
    """Tests for encoding empty lists."""

    def test_encode_empty_list(self) -> None:
        """Empty list encodes to 0xc0."""
        result = encode_rlp([])
        assert result == bytes.fromhex("c0")


class TestEncodeShortList:
    """Tests for short list encoding (0-55 bytes payload)."""

    def test_encode_string_list(self) -> None:
        """List of strings ['dog', 'god', 'cat'] encodes correctly."""
        result = encode_rlp([b"dog", b"god", b"cat"])
        assert result == bytes.fromhex("cc83646f6783676f6483636174")

    def test_encode_multilist(self) -> None:
        """Mixed list ['zw', [4], 1] encodes correctly."""
        # 4 encodes as 0x04 (single byte)
        # 1 encodes as 0x01 (single byte)
        result = encode_rlp([b"zw", [b"\x04"], b"\x01"])
        assert result == bytes.fromhex("c6827a77c10401")

    def test_encode_short_list_max_payload(self) -> None:
        """Short list with 55 bytes of payload uses short list encoding."""
        # Create a list that has exactly 55 bytes of payload
        # Each "a" encodes as 0x61 (single byte), so 55 "a"s = 55 bytes payload
        items: list[RLPItem] = [b"a" for _ in range(SHORT_LIST_MAX_LEN)]
        result = encode_rlp(items)
        assert result[0] == SHORT_LIST_PREFIX + SHORT_LIST_MAX_LEN  # 0xf7


class TestEncodeLongList:
    """Tests for long list encoding (>55 bytes payload)."""

    def test_encode_long_list_four_nested(self) -> None:
        """Long list with 4 nested lists encodes correctly."""
        inner = [b"asdf", b"qwer", b"zxcv"]
        result = encode_rlp([inner, inner, inner, inner])
        expected = bytes.fromhex(
            "f840cf84617364668471776572847a786376cf84617364668471776572847a786376"
            "cf84617364668471776572847a786376cf84617364668471776572847a786376"
        )
        assert result == expected

    def test_encode_long_list_32_nested(self) -> None:
        """Long list with 32 nested lists uses 2-byte length prefix."""
        inner = [b"asdf", b"qwer", b"zxcv"]
        result = encode_rlp([inner] * 32)
        expected_start = bytes.fromhex("f90200")  # 0xf9 = 0xf7 + 2, length = 0x0200 = 512
        assert result[:3] == expected_start

    def test_encode_short_list_11_elements(self) -> None:
        """List with 11 4-byte strings has >55 byte payload, uses long encoding."""
        items: list[RLPItem] = [
            b"asdf",
            b"qwer",
            b"zxcv",
            b"asdf",
            b"qwer",
            b"zxcv",
            b"asdf",
            b"qwer",
            b"zxcv",
            b"asdf",
            b"qwer",
        ]
        result = encode_rlp(items)
        expected = bytes.fromhex(
            "f784617364668471776572847a78637684617364668471776572847a78637684617364"
            "668471776572847a78637684617364668471776572"
        )
        assert result == expected


class TestEncodeNestedLists:
    """Tests for encoding nested list structures."""

    def test_encode_lists_of_lists(self) -> None:
        """Nested empty lists [[[], []], []] encode correctly."""
        result = encode_rlp([[[], []], []])
        assert result == bytes.fromhex("c4c2c0c0c0")

    def test_encode_lists_of_lists_complex(self) -> None:
        """Complex nested structure [[], [[]], [[], [[]]]] encodes correctly."""
        result = encode_rlp([[], [[]], [[], [[]]]])
        assert result == bytes.fromhex("c7c0c1c0c3c0c1c0")


class TestEncodeIntegers:
    """Tests for encoding integers (as byte strings)."""

    def test_encode_zero(self) -> None:
        """Integer 0 encodes as empty string (0x80)."""
        # In RLP, 0 is represented as empty byte string
        result = encode_rlp(b"")
        assert result == bytes.fromhex("80")

    def test_encode_small_integers(self) -> None:
        """Small integers 1-127 encode as single bytes."""
        assert encode_rlp(b"\x01") == bytes.fromhex("01")
        assert encode_rlp(b"\x10") == bytes.fromhex("10")  # 16
        assert encode_rlp(b"\x4f") == bytes.fromhex("4f")  # 79
        assert encode_rlp(b"\x7f") == bytes.fromhex("7f")  # 127

    def test_encode_medium_integers(self) -> None:
        """Integers >= 128 encode as short strings."""
        # 128 = 0x80 (1 byte, but > 0x7f so needs prefix)
        assert encode_rlp(b"\x80") == bytes.fromhex("8180")

        # 1000 = 0x03e8 (2 bytes)
        assert encode_rlp((1000).to_bytes(2, "big")) == bytes.fromhex("8203e8")

        # 100000 = 0x0186a0 (3 bytes)
        assert encode_rlp((100000).to_bytes(3, "big")) == bytes.fromhex("830186a0")

    def test_encode_big_integer_2_pow_256(self) -> None:
        """2^256 encodes as 33-byte string."""
        big_int = 2**256
        big_bytes = big_int.to_bytes(33, "big")
        result = encode_rlp(big_bytes)
        expected = bytes.fromhex(
            "a1010000000000000000000000000000000000000000000000000000000000000000"
        )
        assert result == expected


class TestEncodeTypeErrors:
    """Tests for type validation during encoding."""

    def test_encode_invalid_type_int(self) -> None:
        """Encoding an integer directly raises TypeError."""
        with pytest.raises(TypeError, match=r"Cannot RLP encode type: int"):
            encode_rlp(42)  # type: ignore[arg-type]

    def test_encode_invalid_type_str(self) -> None:
        """Encoding a string directly raises TypeError."""
        with pytest.raises(TypeError, match=r"Cannot RLP encode type: str"):
            encode_rlp("hello")  # type: ignore[arg-type]

    def test_encode_invalid_type_none(self) -> None:
        """Encoding None raises TypeError."""
        with pytest.raises(TypeError, match=r"Cannot RLP encode type: NoneType"):
            encode_rlp(None)  # type: ignore[arg-type]

    def test_encode_invalid_nested_type(self) -> None:
        """Encoding a list with invalid nested type raises TypeError."""
        with pytest.raises(TypeError, match=r"Cannot RLP encode type: int"):
            encode_rlp([b"valid", 123])  # type: ignore[list-item]


class TestDecodeEmptyString:
    """Tests for decoding empty byte strings."""

    def test_decode_empty_string(self) -> None:
        """0x80 decodes to empty string."""
        result = decode_rlp(bytes.fromhex("80"))
        assert result == b""


class TestDecodeSingleByte:
    """Tests for decoding single bytes (0x00-0x7f)."""

    def test_decode_byte_0x00(self) -> None:
        """0x00 decodes to single byte 0x00."""
        result = decode_rlp(bytes.fromhex("00"))
        assert result == b"\x00"

    def test_decode_byte_0x01(self) -> None:
        """0x01 decodes to single byte 0x01."""
        result = decode_rlp(bytes.fromhex("01"))
        assert result == b"\x01"

    def test_decode_byte_0x7f(self) -> None:
        """0x7f decodes to single byte 0x7f."""
        result = decode_rlp(bytes.fromhex("7f"))
        assert result == b"\x7f"

    @pytest.mark.parametrize("byte_val", range(0x00, SINGLE_BYTE_MAX + 1))
    def test_decode_all_single_byte_values(self, byte_val: int) -> None:
        """All single-byte values 0x00-0x7f decode correctly."""
        data = bytes([byte_val])
        result = decode_rlp(data)
        assert result == data


class TestDecodeShortString:
    """Tests for decoding short strings."""

    def test_decode_short_string_dog(self) -> None:
        """0x83646f67 decodes to 'dog'."""
        result = decode_rlp(bytes.fromhex("83646f67"))
        assert result == b"dog"

    def test_decode_short_string_55_bytes(self) -> None:
        """55-byte short string decodes correctly."""
        encoded = bytes.fromhex(
            "b74c6f72656d20697073756d20646f6c6f722073697420616d65742c20"
            "636f6e7365637465747572206164697069736963696e6720656c69"
        )
        result = decode_rlp(encoded)
        assert result == b"Lorem ipsum dolor sit amet, consectetur adipisicing eli"


class TestDecodeLongString:
    """Tests for decoding long strings."""

    def test_decode_long_string_56_bytes(self) -> None:
        """56-byte long string decodes correctly."""
        encoded = bytes.fromhex(
            "b8384c6f72656d20697073756d20646f6c6f722073697420616d65742c20"
            "636f6e7365637465747572206164697069736963696e6720656c6974"
        )
        result = decode_rlp(encoded)
        assert result == b"Lorem ipsum dolor sit amet, consectetur adipisicing elit"

    def test_decode_long_string_1024_bytes(self) -> None:
        """1024-byte string with 2-byte length prefix decodes correctly."""
        # Use simple repeated bytes to avoid codespell false positives.
        expected_data = b"y" * 1024
        encoded = encode_rlp(expected_data)
        result = decode_rlp(encoded)
        assert result == expected_data


class TestDecodeEmptyList:
    """Tests for decoding empty lists."""

    def test_decode_empty_list(self) -> None:
        """0xc0 decodes to empty list."""
        result = decode_rlp(bytes.fromhex("c0"))
        assert result == []


class TestDecodeShortList:
    """Tests for decoding short lists."""

    def test_decode_string_list(self) -> None:
        """Encoded string list decodes correctly."""
        result = decode_rlp(bytes.fromhex("cc83646f6783676f6483636174"))
        assert result == [b"dog", b"god", b"cat"]

    def test_decode_multilist(self) -> None:
        """Mixed list decodes correctly."""
        result = decode_rlp(bytes.fromhex("c6827a77c10401"))
        assert result == [b"zw", [b"\x04"], b"\x01"]


class TestDecodeLongList:
    """Tests for decoding long lists."""

    def test_decode_long_list_four_nested(self) -> None:
        """Long list with 4 nested lists decodes correctly."""
        encoded = bytes.fromhex(
            "f840cf84617364668471776572847a786376cf84617364668471776572847a786376"
            "cf84617364668471776572847a786376cf84617364668471776572847a786376"
        )
        result = decode_rlp(encoded)
        inner = [b"asdf", b"qwer", b"zxcv"]
        assert result == [inner, inner, inner, inner]


class TestDecodeNestedLists:
    """Tests for decoding nested list structures."""

    def test_decode_lists_of_lists(self) -> None:
        """Nested empty lists decode correctly."""
        result = decode_rlp(bytes.fromhex("c4c2c0c0c0"))
        assert result == [[[], []], []]

    def test_decode_lists_of_lists_complex(self) -> None:
        """Complex nested structure decodes correctly."""
        result = decode_rlp(bytes.fromhex("c7c0c1c0c3c0c1c0"))
        assert result == [[], [[]], [[], [[]]]]


class TestDecodeErrors:
    """Tests for decoding error conditions."""

    def test_decode_empty_data(self) -> None:
        """Decoding empty data raises RLPDecodingError."""
        with pytest.raises(RLPDecodingError, match=r"Empty RLP data"):
            decode_rlp(b"")

    def test_decode_trailing_data(self) -> None:
        """Extra bytes after valid RLP raise RLPDecodingError."""
        # Valid empty string (0x80) followed by extra byte
        with pytest.raises(RLPDecodingError, match=r"Trailing data"):
            decode_rlp(bytes.fromhex("8000"))

    def test_decode_short_string_truncated(self) -> None:
        """Truncated short string raises RLPDecodingError."""
        # 0x83 indicates 3-byte string, but only 2 bytes provided
        with pytest.raises(RLPDecodingError, match=r"Data too short"):
            decode_rlp(bytes.fromhex("836465"))  # "de" instead of "dog"

    def test_decode_long_string_truncated_length(self) -> None:
        """Truncated length field in long string raises RLPDecodingError."""
        # 0xb9 indicates 2-byte length, but only 1 byte provided
        with pytest.raises(RLPDecodingError, match=r"Data too short"):
            decode_rlp(bytes.fromhex("b904"))

    def test_decode_long_string_truncated_payload(self) -> None:
        """Truncated payload in long string raises RLPDecodingError."""
        # 0xb838 indicates 56 bytes, but insufficient data provided
        with pytest.raises(RLPDecodingError, match=r"Data too short"):
            decode_rlp(bytes.fromhex("b8380000"))  # Only 2 bytes of payload

    def test_decode_short_list_truncated(self) -> None:
        """Truncated short list raises RLPDecodingError."""
        # 0xc3 indicates 3-byte payload, but only 2 bytes provided
        with pytest.raises(RLPDecodingError, match=r"Data too short"):
            decode_rlp(bytes.fromhex("c38080"))

    def test_decode_long_list_truncated_length(self) -> None:
        """Truncated length field in long list raises RLPDecodingError."""
        # 0xf9 indicates 2-byte length, but only 1 byte provided
        with pytest.raises(RLPDecodingError, match=r"Data too short"):
            decode_rlp(bytes.fromhex("f904"))

    def test_decode_non_canonical_long_string_for_short(self) -> None:
        """Using long string encoding for short string is non-canonical."""
        # 0xb801 indicates long string with 1-byte length containing 0x38 (56)
        # but 0x38 <= 55, so this should be encoded as short string
        with pytest.raises(RLPDecodingError, match=r"Non-canonical.*long string"):
            # 0xb8 followed by length 0x37 (55) - should have used short encoding
            decode_rlp(bytes.fromhex("b837") + b"a" * 55)

    def test_decode_non_canonical_long_list_for_short(self) -> None:
        """Using long list encoding for short list is non-canonical."""
        # 0xf8 followed by length 0x37 (55) - should have used short encoding
        with pytest.raises(RLPDecodingError, match=r"Non-canonical.*long list"):
            decode_rlp(bytes.fromhex("f837") + bytes.fromhex("80") * 55)


class TestDecodeListFunction:
    """Tests for the decode_list convenience function."""

    def test_decode_list_success(self) -> None:
        """decode_list returns list of bytes for flat list."""
        result = decode_rlp_list(bytes.fromhex("cc83646f6783676f6483636174"))
        assert result == [b"dog", b"god", b"cat"]

    def test_decode_list_not_a_list(self) -> None:
        """decode_list raises error when data is not a list."""
        with pytest.raises(RLPDecodingError, match=r"Expected RLP list"):
            decode_rlp_list(bytes.fromhex("83646f67"))  # Encodes "dog", not a list

    def test_decode_list_nested_list_rejected(self) -> None:
        """decode_list raises error when list contains nested lists."""
        with pytest.raises(RLPDecodingError, match=r"Element .* is not bytes"):
            decode_rlp_list(bytes.fromhex("c4c2c0c0c0"))  # [[[], []], []]


class TestEncodeDecodeRoundtrip:
    """Tests for encode/decode roundtrip invariants."""

    @pytest.mark.parametrize(
        "item",
        [
            b"",
            b"\x00",
            b"\x7f",
            b"\x80",
            b"dog",
            b"a" * SHORT_STRING_MAX_LEN,
            b"a" * (SHORT_STRING_MAX_LEN + 1),
            b"a" * 256,
            [],
            [b""],
            [b"a", b"b", b"c"],
            [[b"nested"]],
            [[], [[]], [[], [[]]]],
            [b"mixed", [b"nested", b"list"], b"end"],
        ],
    )
    def test_roundtrip(self, item: RLPItem) -> None:
        """Encoding then decoding returns the original item."""
        encoded = encode_rlp(item)
        decoded = decode_rlp(encoded)
        assert decoded == item

    def test_roundtrip_large_nested_structure(self) -> None:
        """Complex nested structure survives roundtrip."""
        inner = [b"asdf", b"qwer", b"zxcv"]
        structure: RLPItem = [
            inner,
            [inner, inner],
            [[inner], [inner, inner]],
        ]
        encoded = encode_rlp(structure)
        decoded = decode_rlp(encoded)
        assert decoded == structure


class TestOfficialEthereumVectors:
    """Tests using official Ethereum RLP test vectors."""

    def test_emptystring(self) -> None:
        """Official test vector: emptystring."""
        assert encode_rlp(b"") == bytes.fromhex("80")
        assert decode_rlp(bytes.fromhex("80")) == b""

    def test_bytestring00(self) -> None:
        """Official test vector: bytestring00."""
        assert encode_rlp(b"\x00") == bytes.fromhex("00")
        assert decode_rlp(bytes.fromhex("00")) == b"\x00"

    def test_bytestring01(self) -> None:
        """Official test vector: bytestring01."""
        assert encode_rlp(b"\x01") == bytes.fromhex("01")
        assert decode_rlp(bytes.fromhex("01")) == b"\x01"

    def test_bytestring7f(self) -> None:
        """Official test vector: bytestring7F."""
        assert encode_rlp(b"\x7f") == bytes.fromhex("7f")
        assert decode_rlp(bytes.fromhex("7f")) == b"\x7f"

    def test_shortstring(self) -> None:
        """Official test vector: shortstring."""
        assert encode_rlp(b"dog") == bytes.fromhex("83646f67")
        assert decode_rlp(bytes.fromhex("83646f67")) == b"dog"

    def test_shortstring2(self) -> None:
        """Official test vector: shortstring2 (55 bytes - max short string)."""
        data = b"Lorem ipsum dolor sit amet, consectetur adipisicing eli"
        expected = bytes.fromhex(
            "b74c6f72656d20697073756d20646f6c6f722073697420616d65742c20"
            "636f6e7365637465747572206164697069736963696e6720656c69"
        )
        assert encode_rlp(data) == expected
        assert decode_rlp(expected) == data

    def test_longstring(self) -> None:
        """Official test vector: longstring (56 bytes - min long string)."""
        data = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit"
        expected = bytes.fromhex(
            "b8384c6f72656d20697073756d20646f6c6f722073697420616d65742c20"
            "636f6e7365637465747572206164697069736963696e6720656c6974"
        )
        assert encode_rlp(data) == expected
        assert decode_rlp(expected) == data

    def test_emptylist(self) -> None:
        """Official test vector: emptylist."""
        assert encode_rlp([]) == bytes.fromhex("c0")
        assert decode_rlp(bytes.fromhex("c0")) == []

    def test_stringlist(self) -> None:
        """Official test vector: stringlist."""
        data: RLPItem = [b"dog", b"god", b"cat"]
        expected = bytes.fromhex("cc83646f6783676f6483636174")
        assert encode_rlp(data) == expected
        assert decode_rlp(expected) == data

    def test_multilist(self) -> None:
        """Official test vector: multilist."""
        # "zw" = 0x7a77, [4] = 0x04, 1 = 0x01
        data: RLPItem = [b"zw", [b"\x04"], b"\x01"]
        expected = bytes.fromhex("c6827a77c10401")
        assert encode_rlp(data) == expected
        assert decode_rlp(expected) == data

    def test_listsoflists(self) -> None:
        """Official test vector: listsoflists."""
        data: RLPItem = [[[], []], []]
        expected = bytes.fromhex("c4c2c0c0c0")
        assert encode_rlp(data) == expected
        assert decode_rlp(expected) == data

    def test_listsoflists2(self) -> None:
        """Official test vector: listsoflists2."""
        data: RLPItem = [[], [[]], [[], [[]]]]
        expected = bytes.fromhex("c7c0c1c0c3c0c1c0")
        assert encode_rlp(data) == expected
        assert decode_rlp(expected) == data

    def test_dicttest1(self) -> None:
        """Official test vector: dictTest1 (list of key-value pairs)."""
        data: RLPItem = [
            [b"key1", b"val1"],
            [b"key2", b"val2"],
            [b"key3", b"val3"],
            [b"key4", b"val4"],
        ]
        expected = bytes.fromhex(
            "ecca846b6579318476616c31ca846b6579328476616c32"
            "ca846b6579338476616c33ca846b6579348476616c34"
        )
        assert encode_rlp(data) == expected
        assert decode_rlp(expected) == data

    def test_longlist1(self) -> None:
        """Official test vector: longList1."""
        inner: RLPItem = [b"asdf", b"qwer", b"zxcv"]
        data: RLPItem = [inner, inner, inner, inner]
        expected = bytes.fromhex(
            "f840cf84617364668471776572847a786376cf84617364668471776572847a786376"
            "cf84617364668471776572847a786376cf84617364668471776572847a786376"
        )
        assert encode_rlp(data) == expected
        assert decode_rlp(expected) == data


class TestBoundaryConditions:
    """Tests for boundary conditions based on module constants."""

    def test_single_byte_max_boundary(self) -> None:
        """Verify SINGLE_BYTE_MAX boundary (0x7f vs 0x80)."""
        # 0x7f = single byte encoding
        assert encode_rlp(bytes([SINGLE_BYTE_MAX])) == bytes([SINGLE_BYTE_MAX])
        # 0x80 = short string encoding
        assert encode_rlp(bytes([SINGLE_BYTE_MAX + 1])) == bytes([0x81, 0x80])

    def test_short_string_max_boundary(self) -> None:
        """Verify SHORT_STRING_MAX_LEN boundary (55 vs 56 bytes)."""
        # 55 bytes = short string encoding (prefix 0xb7)
        data_55 = b"a" * SHORT_STRING_MAX_LEN
        encoded_55 = encode_rlp(data_55)
        assert encoded_55[0] == SHORT_STRING_PREFIX + SHORT_STRING_MAX_LEN  # 0xb7

        # 56 bytes = long string encoding (prefix 0xb8)
        data_56 = b"a" * (SHORT_STRING_MAX_LEN + 1)
        encoded_56 = encode_rlp(data_56)
        assert encoded_56[0] == LONG_STRING_PREFIX  # 0xb8

    def test_short_list_max_boundary(self) -> None:
        """Verify SHORT_LIST_MAX_LEN boundary (55 vs 56 bytes payload)."""
        # 55 bytes payload = short list encoding (prefix 0xf7)
        items_55: list[RLPItem] = [b"a" for _ in range(SHORT_LIST_MAX_LEN)]
        encoded_55 = encode_rlp(items_55)
        assert encoded_55[0] == SHORT_LIST_PREFIX + SHORT_LIST_MAX_LEN  # 0xf7

        # 56 bytes payload = long list encoding (prefix 0xf8)
        items_56: list[RLPItem] = [b"a" for _ in range(SHORT_LIST_MAX_LEN + 1)]
        encoded_56 = encode_rlp(items_56)
        assert encoded_56[0] == LONG_LIST_PREFIX  # 0xf8

    def test_prefix_boundaries(self) -> None:
        """Verify prefix range boundaries from RLP spec."""
        # Verify constants match RLP specification
        assert SHORT_STRING_PREFIX == 0x80
        assert LONG_STRING_PREFIX == 0xB8
        assert SHORT_LIST_PREFIX == 0xC0
        assert LONG_LIST_PREFIX == 0xF8

        # Short string prefix range: 0x80-0xb7 (length 0-55)
        assert SHORT_STRING_PREFIX + SHORT_STRING_MAX_LEN == 0xB7

        # Short list prefix range: 0xc0-0xf7 (length 0-55)
        assert SHORT_LIST_PREFIX + SHORT_LIST_MAX_LEN == 0xF7
