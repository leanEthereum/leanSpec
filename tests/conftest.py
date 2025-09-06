"""Pytest configuration and shared fixtures."""
from hypothesis import settings

# Create a profile named "no_deadline" with deadline disabled.
settings.register_profile("no_deadline", deadline=None)
settings.load_profile("no_deadline")
