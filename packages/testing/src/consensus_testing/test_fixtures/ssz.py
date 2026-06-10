"""SSZ test fixture format for serialization conformance testing."""

from typing import Any, ClassVar

from pydantic import field_serializer

from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from consensus_testing.test_fixtures.hex_codec import from_hex, to_hex
from lean_spec.base import CamelModel
from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.ssz.boolean import Boolean
from lean_spec.spec.ssz.ssz_base import SSZType


def _serialize_ssz_value(ssz_value: SSZType) -> Any:
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
    if isinstance(ssz_value, Fp):
        return str(ssz_value.value)
    return str(ssz_value)


class SSZFixture(BaseConsensusFixture):
    """
    Emitted vector for SSZ conformance.

    JSON output: typeName, value, rawBytes (decode-failure mode only),
    serialized, root.
    """

    type_name: str
    """SSZ type class name."""

    value: SSZType
    """The SSZ value under test."""

    raw_bytes: str | None = None
    """Hex-encoded malformed input, present in decode-failure mode only."""

    serialized: str
    """Hex SSZ bytes; carries the malformed input verbatim on decode failure."""

    root: str
    """Hex hash_tree_root. Empty in decode-failure mode."""

    @field_serializer("value", when_used="json")
    def serialize_value(self, ssz_value: SSZType) -> Any:
        """Convert an SSZ value to a JSON-safe representation."""
        return _serialize_ssz_value(ssz_value)


class SSZTest(BaseTestSpec):
    """
    Spec for SSZ conformance testing.

    Supports two modes:

    - Roundtrip mode (default): encode `value`, decode back, verify equality
      and compute `hash_tree_root`. JSON output: typeName, value, serialized, root.
    - Decode-failure mode: when `expected_rejection` is set, `raw_bytes` holds
      the malformed input. Generation decodes the input as `type(value)` and
      asserts the decoder rejects it. JSON output keeps the same shape;
      `serialized` holds the malformed bytes and `root` is empty.
    """

    format_name: ClassVar[str] = "ssz_test"
    description: ClassVar[str] = "Tests SSZ serialization roundtrip and hash_tree_root"

    type_name: str
    """SSZ type class name."""

    value: SSZType
    """
    The SSZ value under test.

    Roundtrip mode: the value to encode and round-trip.
    Decode-failure mode: acts as a type tag; its class is used as the decoder.
    Supply any instance of the target type (often a default-constructed one).
    """

    raw_bytes: str | None = None
    """
    Hex-encoded malformed input for decode-failure mode.

    Only consulted when `expected_rejection` is set. Generation decodes these
    bytes using `type(value).decode_bytes` and asserts the decoder raises.
    """

    def generate(self) -> SSZFixture:
        """
        Verify SSZ roundtrip or decode-failure and produce the reference output.

        Returns:
            The emitted vector with serialized bytes and root populated.

        Raises:
            AssertionError:
                - In roundtrip mode, if `decode(encode(value)) != value`.
                - In decode-failure mode, if the decoder does not reject.
        """
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
        Run the decode-failure path: assert decoding `raw_bytes` raises.

        The class of `value` is used as the decoder. `serialized` carries
        the malformed bytes verbatim so consumers can reproduce the input.

        Raises:
            AssertionError: If the decoder succeeds.
            ValueError: If `raw_bytes` is missing.
        """
        if self.raw_bytes is None:
            raise ValueError("raw_bytes is required when expected_rejection is set")

        raw = from_hex(self.raw_bytes)
        decoder = type(self.value)
        exception_raised: Exception | None = None
        try:
            decoder.decode_bytes(raw)
        except Exception as exception:
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
