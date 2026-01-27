"""
Shared pytest fixtures for yamux multiplexing tests.

Provides mock session and stream factories.
"""

from __future__ import annotations

import pytest

from lean_spec.subspecs.networking.transport.yamux.session import YamuxSession, YamuxStream
from tests.lean_spec.helpers import MockNoiseSession

# -----------------------------------------------------------------------------
# Session Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture
def mock_noise_session() -> MockNoiseSession:
    """Mock NoiseSession for yamux testing."""
    return MockNoiseSession()


@pytest.fixture
def make_yamux_session(mock_noise_session: MockNoiseSession):
    """
    Factory fixture for YamuxSession instances.

    Returns a callable that creates sessions with configurable initiator status.
    """

    def _make(is_initiator: bool = True) -> YamuxSession:
        return YamuxSession(noise=mock_noise_session, is_initiator=is_initiator)

    return _make


@pytest.fixture
def make_yamux_stream():
    """
    Factory fixture for YamuxStream instances.

    Returns a callable that creates streams with configurable parameters.
    """

    def _make(
        stream_id: int = 1,
        is_initiator: bool = True,
    ) -> YamuxStream:
        noise = MockNoiseSession()
        session = YamuxSession(noise=noise, is_initiator=is_initiator)
        return YamuxStream(
            stream_id=stream_id,
            session=session,
            is_initiator=is_initiator,
        )

    return _make
