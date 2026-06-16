"""Shared helpers for the API server tests."""

from dataclasses import dataclass


@dataclass(slots=True)
class AggregatorRoleStub:
    """Minimal stand-in exposing only the aggregator flag the endpoints touch."""

    is_aggregator: bool = False
