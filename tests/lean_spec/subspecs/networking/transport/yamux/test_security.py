"""Security edge case tests for yamux protocol.

These tests prevent regression of critical security vulnerabilities:
1. Max frame size enforcement (DoS prevention)
2. Flow control violation detection
3. Byte-bounded buffer overflow prevention

References:
    - https://github.com/hashicorp/yamux/blob/master/spec.md
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from lean_spec.subspecs.networking.transport.yamux.frame import (
    YAMUX_HEADER_SIZE,
    YAMUX_INITIAL_WINDOW,
    YAMUX_MAX_FRAME_SIZE,
    YAMUX_VERSION,
    YamuxError,
    YamuxFlags,
    YamuxFrame,
    YamuxType,
)
from lean_spec.subspecs.networking.transport.yamux.session import (
    MAX_BUFFER_BYTES,
    YamuxSession,
    YamuxStream,
)


class TestMaxFrameSizeEnforcement:
    """Tests for max frame size enforcement (DoS prevention).

    Security context: Without frame size limits, a malicious peer could claim
    a massive length in the header (e.g., 2GB), causing memory exhaustion when
    the receiver tries to allocate/process it.
    """

    def test_data_frame_exceeding_max_size_raises_error(self) -> None:
        """DATA frame with payload larger than YAMUX_MAX_FRAME_SIZE raises YamuxError."""
        # Create a header claiming 2GB payload (way over the 1MB limit)
        oversized_length = 2 * 1024 * 1024 * 1024  # 2GB
        header = struct.pack(
            ">BBHII",
            YAMUX_VERSION,
            YamuxType.DATA,
            YamuxFlags.NONE,
            1,  # stream_id
            oversized_length,
        )

        with pytest.raises(YamuxError, match=r"Frame payload too large"):
            YamuxFrame.decode(header)

    def test_data_frame_at_exactly_max_size_succeeds(self) -> None:
        """DATA frame with payload exactly at YAMUX_MAX_FRAME_SIZE is accepted."""
        header = struct.pack(
            ">BBHII",
            YAMUX_VERSION,
            YamuxType.DATA,
            YamuxFlags.NONE,
            1,  # stream_id
            YAMUX_MAX_FRAME_SIZE,  # Exactly at limit (1MB)
        )

        frame = YamuxFrame.decode(header)

        assert frame.frame_type == YamuxType.DATA
        assert frame.length == YAMUX_MAX_FRAME_SIZE

    def test_data_frame_one_byte_over_max_size_raises_error(self) -> None:
        """DATA frame with payload 1 byte over YAMUX_MAX_FRAME_SIZE raises YamuxError."""
        header = struct.pack(
            ">BBHII",
            YAMUX_VERSION,
            YamuxType.DATA,
            YamuxFlags.NONE,
            1,  # stream_id
            YAMUX_MAX_FRAME_SIZE + 1,  # 1 byte over limit
        )

        with pytest.raises(YamuxError, match=r"Frame payload too large"):
            YamuxFrame.decode(header)

    def test_window_update_with_large_length_is_valid(self) -> None:
        """WINDOW_UPDATE frames with large length are NOT rejected.

        For WINDOW_UPDATE frames, the length field is a window delta, not a
        payload size. Large deltas are valid and should not trigger the frame
        size limit check.
        """
        # WINDOW_UPDATE with a very large delta (larger than max frame size)
        large_delta = YAMUX_MAX_FRAME_SIZE * 2
        header = struct.pack(
            ">BBHII",
            YAMUX_VERSION,
            YamuxType.WINDOW_UPDATE,
            YamuxFlags.NONE,
            1,  # stream_id
            large_delta,
        )

        frame = YamuxFrame.decode(header)

        assert frame.frame_type == YamuxType.WINDOW_UPDATE
        assert frame.length == large_delta

    def test_ping_with_large_opaque_value_is_valid(self) -> None:
        """PING frames with large opaque values are valid."""
        large_opaque = 0xFFFFFFFF  # Maximum 32-bit value
        header = struct.pack(
            ">BBHII",
            YAMUX_VERSION,
            YamuxType.PING,
            YamuxFlags.NONE,
            0,  # stream_id (session-level)
            large_opaque,
        )

        frame = YamuxFrame.decode(header)

        assert frame.frame_type == YamuxType.PING
        assert frame.length == large_opaque

    def test_go_away_with_large_code_is_valid(self) -> None:
        """GO_AWAY frames with large error codes are valid."""
        header = struct.pack(
            ">BBHII",
            YAMUX_VERSION,
            YamuxType.GO_AWAY,
            YamuxFlags.NONE,
            0,  # stream_id (session-level)
            0xFFFFFFFF,  # Large error code
        )

        frame = YamuxFrame.decode(header)

        assert frame.frame_type == YamuxType.GO_AWAY
        assert frame.length == 0xFFFFFFFF


class TestFlowControlViolationDetection:
    """Tests for flow control violation detection.

    Security context: A malicious peer could ignore flow control and flood
    the receiver with more data than advertised window allows. This must
    trigger a stream reset to protect against memory exhaustion.
    """

    def test_data_exceeding_recv_window_triggers_reset(self) -> None:
        """Receiving data that exceeds recv_window triggers stream reset."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        # Initial window is YAMUX_INITIAL_WINDOW (256KB)
        assert stream._recv_window == YAMUX_INITIAL_WINDOW

        # Try to receive data larger than the window
        oversized_data = b"x" * (YAMUX_INITIAL_WINDOW + 1)
        stream._handle_data(oversized_data)

        # Stream should be reset due to flow control violation
        assert stream._reset is True
        assert stream._read_closed is True
        assert stream._write_closed is True

    def test_data_exactly_at_window_limit_succeeds(self) -> None:
        """Receiving data exactly at recv_window limit succeeds."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        # Data exactly at the window limit should succeed
        exact_data = b"x" * YAMUX_INITIAL_WINDOW
        stream._handle_data(exact_data)

        # Stream should NOT be reset
        assert stream._reset is False
        assert not stream._recv_buffer.empty()

    def test_data_one_byte_over_window_triggers_reset(self) -> None:
        """Receiving data 1 byte over recv_window triggers reset."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        # First, consume some of the window
        initial_data = b"x" * 100
        stream._handle_data(initial_data)
        assert stream._reset is False

        # Now try to send more than remaining window allows
        remaining_window = stream._recv_window
        oversized_data = b"y" * (remaining_window + 1)
        stream._handle_data(oversized_data)

        # Stream should be reset
        assert stream._reset is True

    def test_flow_control_violation_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Flow control violation logs a warning message."""
        stream = _create_mock_stream(stream_id=42, is_initiator=True)

        # Exceed the window
        oversized_data = b"x" * (YAMUX_INITIAL_WINDOW + 100)
        stream._handle_data(oversized_data)

        # Check that warning was logged
        assert "flow control violation" in caplog.text.lower()
        assert "42" in caplog.text  # stream_id should be in the log

    def test_recv_window_decreases_on_valid_data(self) -> None:
        """recv_window decreases when valid data is received."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        initial_window = stream._recv_window

        data = b"hello world"
        stream._handle_data(data)

        assert stream._recv_window == initial_window - len(data)


class TestByteBufferOverflowPrevention:
    """Tests for byte-bounded buffer overflow prevention.

    Security context: Even with slot-based buffer limits, a malicious peer
    could send large chunks that fit in few slots but consume huge memory.
    Byte-level limits prevent this attack.
    """

    def test_buffer_exceeding_max_bytes_triggers_reset(self) -> None:
        """Buffering data exceeding MAX_BUFFER_BYTES triggers stream reset."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        # First add some data to the buffer
        initial_data = b"x" * (MAX_BUFFER_BYTES - 100)
        stream._handle_data(initial_data)
        assert stream._reset is False

        # Now add data that would exceed the limit
        excess_data = b"y" * 200  # This would push us over MAX_BUFFER_BYTES
        stream._handle_data(excess_data)

        # Stream should be reset
        assert stream._reset is True

    def test_buffer_exactly_at_max_bytes_succeeds(self) -> None:
        """Buffering data exactly at MAX_BUFFER_BYTES succeeds."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        # Add data exactly at the buffer limit
        # Note: MAX_BUFFER_BYTES == YAMUX_INITIAL_WINDOW, so this also tests
        # the interaction between flow control and buffer limits
        exact_data = b"x" * MAX_BUFFER_BYTES
        stream._handle_data(exact_data)

        # Stream should NOT be reset (exactly at limit is OK)
        assert stream._reset is False
        assert not stream._recv_buffer.empty()

    def test_buffer_one_byte_over_max_bytes_triggers_reset(self) -> None:
        """Buffering data 1 byte over MAX_BUFFER_BYTES triggers reset."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        # First fill buffer almost to limit
        stream._current_buffer_bytes = MAX_BUFFER_BYTES - 1
        stream._recv_window = MAX_BUFFER_BYTES  # Ensure window doesn't block us

        # Try to add just 2 bytes (1 over the limit)
        stream._handle_data(b"xy")

        # Stream should be reset
        assert stream._reset is True

    def test_buffer_overflow_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Buffer overflow logs a warning message."""
        stream = _create_mock_stream(stream_id=99, is_initiator=True)

        # Fill buffer close to limit
        stream._current_buffer_bytes = MAX_BUFFER_BYTES - 10
        stream._recv_window = MAX_BUFFER_BYTES  # Ensure window allows

        # Exceed buffer limit
        stream._handle_data(b"x" * 20)

        # Check that warning was logged
        assert "buffer overflow" in caplog.text.lower()
        assert "99" in caplog.text  # stream_id should be in the log


class TestBufferBytesTracking:
    """Tests for accurate _current_buffer_bytes tracking.

    Security context: Accurate byte tracking is essential to prevent memory
    leaks and ensure buffer limits are properly enforced.
    """

    def test_handle_data_increments_buffer_bytes(self) -> None:
        """_handle_data increments _current_buffer_bytes correctly."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        assert stream._current_buffer_bytes == 0

        data1 = b"hello"
        stream._handle_data(data1)
        assert stream._current_buffer_bytes == len(data1)

        data2 = b" world"
        stream._handle_data(data2)
        assert stream._current_buffer_bytes == len(data1) + len(data2)

    def test_read_decrements_buffer_bytes(self) -> None:
        """read() decrements _current_buffer_bytes correctly."""

        async def run_test() -> None:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)

            data = b"test data here"
            stream._handle_data(data)
            assert stream._current_buffer_bytes == len(data)

            await stream.read()
            assert stream._current_buffer_bytes == 0

        asyncio.run(run_test())

    def test_buffer_bytes_tracking_accuracy_across_operations(self) -> None:
        """Buffer bytes tracking remains accurate across multiple operations."""

        async def run_test() -> None:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)

            # Add data in chunks
            chunks = [b"chunk1", b"chunk22", b"chunk333"]
            total_bytes = 0

            for chunk in chunks:
                stream._handle_data(chunk)
                total_bytes += len(chunk)
                assert stream._current_buffer_bytes == total_bytes

            # Read data and verify decrement
            for chunk in chunks:
                await stream.read()
                total_bytes -= len(chunk)
                assert stream._current_buffer_bytes == total_bytes

            assert stream._current_buffer_bytes == 0

        asyncio.run(run_test())

    def test_buffer_bytes_not_incremented_when_read_closed(self) -> None:
        """_current_buffer_bytes is not incremented when stream is read-closed."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        stream._read_closed = True

        stream._handle_data(b"should be ignored")

        assert stream._current_buffer_bytes == 0

    def test_buffer_bytes_not_incremented_when_reset(self) -> None:
        """_current_buffer_bytes is not incremented when stream is reset."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        stream._reset = True

        stream._handle_data(b"should be ignored")

        assert stream._current_buffer_bytes == 0


class TestSecurityEdgeCaseCombinations:
    """Tests for combinations of security edge cases.

    These tests verify that multiple security mechanisms work correctly together.
    """

    def test_flow_control_checked_before_buffer_limit(self) -> None:
        """Flow control is checked before buffer limit in _handle_data.

        When both limits would be exceeded, the flow control check should
        trigger first since it comes before the buffer check in the code.
        """
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        # Set up a scenario where both limits would be exceeded
        stream._recv_window = 100
        stream._current_buffer_bytes = MAX_BUFFER_BYTES - 50

        # Try to send 200 bytes (exceeds both window and buffer)
        stream._handle_data(b"x" * 200)

        # Stream should be reset (flow control violation)
        assert stream._reset is True

    def test_multiple_small_chunks_respect_buffer_limit(self) -> None:
        """Multiple small chunks that sum to exceed buffer limit trigger reset."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        # Send many small chunks to approach the limit
        chunk_size = 1000
        chunks_to_fill = MAX_BUFFER_BYTES // chunk_size

        for _ in range(chunks_to_fill):
            stream._handle_data(b"x" * chunk_size)
            if stream._reset:
                break  # Window limit might hit first

        # Ensure we're close to but not over buffer limit if not reset
        if not stream._reset:
            # One more chunk should trigger reset or succeed based on window
            remaining = MAX_BUFFER_BYTES - stream._current_buffer_bytes
            if stream._recv_window > remaining:
                # Window allows, but buffer would exceed
                stream._handle_data(b"x" * (remaining + 1))
                assert stream._reset is True

    def test_reset_stream_ignores_all_subsequent_data(self) -> None:
        """Once a stream is reset, all subsequent data is ignored."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        # Trigger reset via flow control violation
        oversized_data = b"x" * (YAMUX_INITIAL_WINDOW + 1)
        stream._handle_data(oversized_data)
        assert stream._reset is True

        initial_buffer_bytes = stream._current_buffer_bytes

        # Try to send more data
        stream._handle_data(b"more data")

        # Buffer should not have changed
        assert stream._current_buffer_bytes == initial_buffer_bytes
        assert stream._recv_buffer.empty()


class TestSecurityConstants:
    """Tests verifying security-related constants are properly defined."""

    def test_max_frame_size_is_1mb(self) -> None:
        """YAMUX_MAX_FRAME_SIZE is 1MB."""
        assert YAMUX_MAX_FRAME_SIZE == 1 * 1024 * 1024
        assert YAMUX_MAX_FRAME_SIZE == 1048576

    def test_max_buffer_bytes_equals_initial_window(self) -> None:
        """MAX_BUFFER_BYTES equals YAMUX_INITIAL_WINDOW (256KB)."""
        assert MAX_BUFFER_BYTES == YAMUX_INITIAL_WINDOW
        assert MAX_BUFFER_BYTES == 256 * 1024

    def test_initial_window_is_256kb(self) -> None:
        """YAMUX_INITIAL_WINDOW is 256KB."""
        assert YAMUX_INITIAL_WINDOW == 256 * 1024
        assert YAMUX_INITIAL_WINDOW == 262144

    def test_header_size_is_12_bytes(self) -> None:
        """YAMUX_HEADER_SIZE is 12 bytes."""
        assert YAMUX_HEADER_SIZE == 12


# Helper functions for testing


def _create_mock_stream(stream_id: int, is_initiator: bool) -> YamuxStream:
    """Create a mock YamuxStream for testing."""
    session = _create_mock_session(is_initiator=is_initiator)
    return YamuxStream(
        stream_id=stream_id,
        session=session,
        is_initiator=is_initiator,
    )


def _create_mock_session(is_initiator: bool) -> YamuxSession:
    """Create a mock YamuxSession for testing."""
    noise = MockNoiseSession()
    return YamuxSession(noise=noise, is_initiator=is_initiator)


class MockNoiseSession:
    """Mock NoiseSession for testing yamux."""

    def __init__(self) -> None:
        self._written: list[bytes] = []
        self._to_read: list[bytes] = []
        self._closed = False

    async def write(self, plaintext: bytes) -> None:
        self._written.append(plaintext)

    async def read(self) -> bytes:
        if self._to_read:
            return self._to_read.pop(0)
        return b""

    async def close(self) -> None:
        self._closed = True
