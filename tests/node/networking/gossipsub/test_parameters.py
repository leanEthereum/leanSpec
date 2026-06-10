"""Tests for gossipsub parameters."""

from lean_spec.node.networking.gossipsub import GossipsubParameters


class TestGossipsubParameters:
    """Test suite for GossipSub protocol parameters."""

    def test_default_parameters(self) -> None:
        """Test default GossipSub parameters."""
        params = GossipsubParameters()

        # Test Ethereum spec values
        assert params.d == 8
        assert params.d_low == 6
        assert params.d_high == 12
        assert params.d_lazy == 6
        assert params.heartbeat_interval_secs == 0.7
        assert params.fanout_ttl_secs == 60
        assert params.mcache_length == 6
        assert params.mcache_gossip == 3

        # Test relationships
        assert params.d_low < params.d < params.d_high
        assert params.d_lazy <= params.d
        assert params.mcache_gossip <= params.mcache_length
