"""Pytest configuration and shared fixtures."""

from hypothesis import settings

import lean_spec.runtime_config

# Create a profile named "no_deadline" with deadline disabled.
settings.register_profile("no_deadline", deadline=None)
settings.load_profile("no_deadline")

# Enable test mode for XMSS signature scheme
# This uses smaller parameters (TEST_CONFIG) for faster test execution
lean_spec.runtime_config.USE_TEST_SCHEME = True
