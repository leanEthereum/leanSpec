"""SSZ test fixture format for serialization conformance testing."""

from typing import Any, ClassVar

from pydantic import ValidationError, field_serializer
from ssz import Boolean, SSZError, SSZType, hash_tree_root

from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from consensus_testing.test_fixtures.hex_codec import from_hex, to_hex
from lean_spec.base import CamelModel
from lean_spec.spec.ssz_types import ContainerInvariantError


class SSZFixture(BaseConsensusFixture):
    """Emitted vector for SSZ conformance."""

    type_name: str
    """SSZ type class name."""

    value: SSZType
    """The SSZ value under test."""

    raw_bytes: str | None = None
    """Hex malformed input, present in decode-failure mode only."""

    serialized: str
    """Hex SSZ bytes, or the malformed input verbatim on decode failure."""

    root: str
    """Hex tree root, empty in decode-failure mode."""

    @field_serializer("value", when_used="json")
    def serialize_value(self, ssz_value: SSZType) -> Any:
        """Convert an SSZ value to a JSON-safe representation."""
        if isinstance(ssz_value, CamelModel):
            return ssz_value.to_json()
        # Boolean before int — Boolean subclasses int.
        if isinstance(ssz_value, Boolean):
            return bool(ssz_value)
        if isinstance(ssz_value, bytes):
            return to_hex(ssz_value)
        if isinstance(ssz_value, int):
            return str(ssz_value)
        return str(ssz_value)


class SSZTest(BaseTestSpec):
    """Spec for SSZ conformance, running either a roundtrip or a decode-failure check."""

    format_name: ClassVar[str] = "ssz_test"
    description: ClassVar[str] = "Tests SSZ serialization roundtrip and hash_tree_root"

    type_name: str
    """SSZ type class name."""

    value: SSZType
    """The SSZ value under test.

    In decode-failure mode only its class matters, since the class supplies the decoder."""

    raw_bytes: str | None = None
    """Hex malformed input, consulted only in decode-failure mode."""

    def generate(self) -> SSZFixture:
        """Verify SSZ roundtrip or decode-failure and produce the reference output."""
        if self.expected_rejection is not None:
            return self._generate_decode_failure()

        ssz_bytes = self.value.encode_bytes()
        decoded = self.value.decode_bytes(ssz_bytes)

        assert decoded == self.value, (
            f"SSZ roundtrip failed for {self.type_name}: "
            f"original != decoded\n"
            f"Original: {self.value}\n"
            f"Decoded: {decoded}"
        )

        root = hash_tree_root(self.value)

        return SSZFixture(
            type_name=self.type_name,
            value=self.value,
            raw_bytes=self.raw_bytes,
            serialized=to_hex(ssz_bytes),
            root=to_hex(root),
        )

    def _generate_decode_failure(self) -> SSZFixture:
        """
        Assert decoding the malformed bytes raises.

        The bytes are emitted verbatim so consumers can reproduce the rejected input.
        """
        if self.raw_bytes is None:
            raise ValueError("raw_bytes is required when expected_rejection is set")

        raw = from_hex(self.raw_bytes)
        decoder = type(self.value)
        exception_raised: Exception | None = None
        try:
            decoder.decode_bytes(raw)
        except (SSZError, ValidationError, ContainerInvariantError) as exception:
            # Anything else is a bug in the filler, not an input every client must reject.
            exception_raised = exception

        return SSZFixture(
            type_name=self.type_name,
            value=self.value,
            raw_bytes=self.raw_bytes,
            serialized=to_hex(raw),
            root="",
            rejection_reason=self.assert_decode_rejection(
                exception_raised, f"{decoder.__name__}.decode_bytes"
            ),
        )
