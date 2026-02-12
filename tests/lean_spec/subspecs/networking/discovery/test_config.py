"""Tests for Discovery v5 configuration."""

import pytest
from pydantic import ValidationError

from lean_spec.subspecs.networking.discovery.config import (
    ALPHA,
    BOND_EXPIRY_SECS,
    HANDSHAKE_TIMEOUT_SECS,
    K_BUCKET_SIZE,
    MAX_NODES_RESPONSE,
    REQUEST_TIMEOUT_SECS,
    DiscoveryConfig,
)


class TestDiscoveryConfig:
    """Tests for DiscoveryConfig Pydantic model."""

    def test_defaults_match_module_constants(self):
        """Default config values match the module-level constants."""
        config = DiscoveryConfig()

        assert config.k_bucket_size == K_BUCKET_SIZE
        assert config.alpha == ALPHA
        assert config.request_timeout_secs == REQUEST_TIMEOUT_SECS
        assert config.handshake_timeout_secs == HANDSHAKE_TIMEOUT_SECS
        assert config.max_nodes_response == MAX_NODES_RESPONSE
        assert config.bond_expiry_secs == BOND_EXPIRY_SECS

    def test_custom_values_accepted(self):
        """Custom values override defaults."""
        config = DiscoveryConfig(
            k_bucket_size=32,
            alpha=5,
            request_timeout_secs=2.0,
            handshake_timeout_secs=5.0,
            max_nodes_response=8,
            bond_expiry_secs=3600,
        )

        assert config.k_bucket_size == 32
        assert config.alpha == 5
        assert config.request_timeout_secs == 2.0
        assert config.handshake_timeout_secs == 5.0
        assert config.max_nodes_response == 8
        assert config.bond_expiry_secs == 3600

    def test_strict_model_rejects_extra_fields(self):
        """DiscoveryConfig rejects unknown fields (strict mode)."""
        with pytest.raises(ValidationError):
            DiscoveryConfig(unknown_field="oops")  # type: ignore[call-arg]
