"""Pytest configuration and shared fixtures."""

import os

from hypothesis import settings

# Set LEAN_ENV=test before importing any modules that depend on it
if "LEAN_ENV" not in os.environ:
    os.environ["LEAN_ENV"] = "test"

import lean_spec.subspecs.xmss as xmss

# Create a profile named "no_deadline" with deadline disabled.
settings.register_profile("no_deadline", deadline=None)
settings.load_profile("no_deadline")
