"""SSZ test fixture format for serialization conformance testing."""

from typing import Any, ClassVar

from pydantic import field_serializer

from lean_spec.types.container import Container

from .base import BaseConsensusFixture


class SSZTest(BaseConsensusFixture):
    """
    Test fixture for SSZ serialization/deserialization conformance.

    Tests roundtrip serialization for SSZ containers.

    Structure:
        type_name: Name of the container class
        value: The container instance
        serialized: Hex-encoded SSZ bytes (computed)
    """

    format_name: ClassVar[str] = "ssz"
    description: ClassVar[str] = "Tests SSZ serialization roundtrip"

    type_name: str
    """Name of the container class being tested."""

    value: Container
    """The container instance to test."""

    serialized: str = ""
    """Hex-encoded SSZ serialized bytes (computed during make_fixture)."""

    @field_serializer("value", when_used="json")
    def serialize_value(self, value: Container) -> dict[str, Any]:
        """Serialize the container value to JSON using its native serialization."""
        return value.to_json()

    def make_fixture(self) -> "SSZTest":
        """
        Generate the fixture by testing SSZ roundtrip.

        1. Serialize the value to SSZ bytes
        2. Deserialize the bytes back to a container
        3. Verify the roundtrip produces the same value

        Returns:
            SSZTest with computed serialized field.

        Raises:
            AssertionError: If roundtrip fails.
        """
        # Serialize to SSZ bytes
        ssz_bytes = self.value.encode_bytes()

        # Deserialize back
        container_cls = type(self.value)
        decoded = container_cls.decode_bytes(ssz_bytes)

        # Verify roundtrip
        assert decoded == self.value, (
            f"SSZ roundtrip failed for {self.type_name}: "
            f"original != decoded\n"
            f"Original: {self.value}\n"
            f"Decoded: {decoded}"
        )

        # Return fixture with computed serialized field
        return self.model_copy(update={"serialized": "0x" + ssz_bytes.hex()})
