"""Tests for snappy literal and copy tag encoding/decoding."""

from __future__ import annotations

import pytest

from lean_spec.node.snappy.encoding import (
    decode_tag,
    encode_copy_tag,
    encode_literal_tag,
)


class TestTagEncoding:
    """Tests for literal and copy tag encoding/decoding."""

    def test_literal_inline_length(self) -> None:
        """Literal lengths 1-60 encode inline."""
        for length in [1, 30, 60]:
            tag = encode_literal_tag(length)
            assert len(tag) == 1
            tag_type, decoded_length, copy_offset, consumed = decode_tag(tag)
            assert tag_type == "literal"
            assert decoded_length == length
            assert copy_offset == 0
            assert consumed == 1

    def test_literal_extended_length(self) -> None:
        """Literal lengths > 60 use extended encoding."""
        for length in [61, 100, 256, 1000, 65536]:
            tag = encode_literal_tag(length)
            assert len(tag) > 1
            tag_type, decoded_length, copy_offset, consumed = decode_tag(tag)
            assert tag_type == "literal"
            assert decoded_length == length
            assert copy_offset == 0

    def test_copy_1_encoding(self) -> None:
        """Copy-1 encoding (2 bytes) for short offsets and lengths 4-11."""
        for length in [4, 7, 11]:
            for offset in [1, 100, 2047]:
                tag = encode_copy_tag(length, offset)
                assert len(tag) == 2
                tag_type, decoded_length, decoded_offset, consumed = decode_tag(tag)
                assert tag_type == "copy"
                assert decoded_length == length
                assert decoded_offset == offset
                assert consumed == 2

    def test_copy_2_encoding(self) -> None:
        """Copy-2 encoding (3 bytes) for medium offsets."""
        tag = encode_copy_tag(3, 100)  # Length outside [4, 11] forces copy-2
        assert len(tag) == 3

        tag = encode_copy_tag(10, 3000)  # Large offset forces copy-2
        assert len(tag) == 3

        tag_type, decoded_length, decoded_offset, consumed = decode_tag(tag)
        assert tag_type == "copy"
        assert decoded_length == 10
        assert decoded_offset == 3000

    def test_copy_4_encoding(self) -> None:
        """Copy-4 encoding (5 bytes) for large offsets."""
        tag = encode_copy_tag(10, 70000)
        assert len(tag) == 5

        tag_type, decoded_length, decoded_offset, consumed = decode_tag(tag)
        assert tag_type == "copy"
        assert decoded_length == 10
        assert decoded_offset == 70000

    def test_invalid_literal_length_raises(self) -> None:
        """Literal length < 1 raises ValueError."""
        with pytest.raises(ValueError) as exception_info:
            encode_literal_tag(0)
        assert str(exception_info.value) == "Literal length must be >= 1, got 0"

    def test_invalid_copy_params_raise(self) -> None:
        """Invalid copy parameters raise ValueError."""
        with pytest.raises(ValueError) as exception_info:
            encode_copy_tag(0, 100)
        assert str(exception_info.value) == "Copy length must be >= 1, got 0"
        with pytest.raises(ValueError) as exception_info:
            encode_copy_tag(4, 0)
        assert str(exception_info.value) == "Copy offset must be >= 1, got 0"
