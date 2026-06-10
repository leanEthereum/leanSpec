"""Tests for the event source protocol module."""

from __future__ import annotations

from lean_spec.node.networking.client.event_source import SUPPORTED_PROTOCOLS
from lean_spec.node.networking.config import (
    GOSSIPSUB_DEFAULT_PROTOCOL_ID,
    GOSSIPSUB_PROTOCOL_ID_V12,
)
from lean_spec.node.networking.reqresp.handler import REQRESP_PROTOCOL_IDS


class TestSupportedProtocols:
    """
    Verify the set of protocol IDs advertised during connection setup.

    The node advertises gossipsub v1.2 (for IDONTWANT bandwidth optimization)
    and all req/resp protocol IDs.
    The set must be immutable to prevent accidental mutation at runtime.
    """

    def test_contains_gossipsub_default(self) -> None:
        """Includes the default gossipsub protocol ID."""
        assert GOSSIPSUB_DEFAULT_PROTOCOL_ID in SUPPORTED_PROTOCOLS

    def test_contains_gossipsub_v12(self) -> None:
        """Includes gossipsub v1.2 for IDONTWANT bandwidth optimization."""
        assert GOSSIPSUB_PROTOCOL_ID_V12 in SUPPORTED_PROTOCOLS

    def test_contains_all_reqresp_protocols(self) -> None:
        """Includes all request/response protocol IDs."""
        assert REQRESP_PROTOCOL_IDS <= SUPPORTED_PROTOCOLS

    def test_is_frozenset(self) -> None:
        """Protocol set is immutable."""
        assert isinstance(SUPPORTED_PROTOCOLS, frozenset)

    def test_exact_composition(self) -> None:
        """Equals the union of gossipsub and reqresp protocol IDs."""
        expected_protocols = frozenset({GOSSIPSUB_DEFAULT_PROTOCOL_ID, GOSSIPSUB_PROTOCOL_ID_V12})
        expected_protocols |= REQRESP_PROTOCOL_IDS
        assert SUPPORTED_PROTOCOLS == expected_protocols
