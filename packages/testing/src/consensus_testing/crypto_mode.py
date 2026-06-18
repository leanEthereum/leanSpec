"""Mock the Rust aggregation prover at the FFI boundary, from the test layer."""

import hashlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from enum import StrEnum

import lean_spec.spec.forks.lstar.containers.aggregation as aggregation

MOCK_PROOF_PREFIX = b"\x00MOCKED-AGGREGATION-PROOF\x00"
"""Sentinel opening every placeholder proof the mocked prover emits."""


class CryptoMode(StrEnum):
    """Whether aggregation runs the real Rust prover or an in-process mock."""

    REAL = "real"
    MOCKED = "mocked"


class AggregationProver:
    """Process-wide control over how aggregation proofs are built and checked."""

    _prover_names = (
        "aggregate_single_message",
        "merge_many_single_message_proof",
        "split_multi_message_proof_by_message",
    )
    """Spec-module bindings that build a proof and return an (info, wire) pair."""

    _verifier_names = ("verify_single_message_proof", "verify_multi_message_proof_with_messages")
    """Spec-module bindings that verify a proof and raise on rejection."""

    _mode = CryptoMode.MOCKED
    """The mode every vector in this process is built under."""

    @classmethod
    def set_mode(cls, mode: CryptoMode) -> None:
        """Select the process-wide crypto mode for the run."""
        cls._mode = mode

    @classmethod
    def get_mode(cls) -> CryptoMode:
        """Return the process-wide crypto mode."""
        return cls._mode

    @classmethod
    @contextmanager
    def mocked(cls) -> Iterator[None]:
        """
        Swap the Rust prover bindings on the spec module for in-process stubs.

        - Provers return a placeholder proof.
        - Verifiers accept that placeholder.
        """
        originals = {
            name: getattr(aggregation, name) for name in (*cls._prover_names, *cls._verifier_names)
        }

        def prove(
            *positional_arguments: object, **_keyword_arguments: object
        ) -> tuple[None, bytes]:
            # Distinct inputs hash to distinct bytes, so two blocks never collide.
            fingerprint = repr(positional_arguments).encode()
            return None, MOCK_PROOF_PREFIX + hashlib.sha256(fingerprint).digest()

        def make_verifier(real_verifier: Callable[..., None]) -> Callable[..., None]:
            def verify(*positional_arguments: object, **keyword_arguments: object) -> None:
                # Accept any sentinel-prefixed placeholder unchecked.
                # Invariant: sound only because proof vectors carry the real-crypto marker.
                carries_placeholder = any(
                    isinstance(argument, bytes) and argument.startswith(MOCK_PROOF_PREFIX)
                    for argument in positional_arguments
                )
                if carries_placeholder:
                    return None
                # A vector mixing real and mocked inputs can still pass real bytes.
                # Fall through to the real verifier for those.
                return real_verifier(*positional_arguments, **keyword_arguments)

            return verify

        try:
            for name in cls._prover_names:
                setattr(aggregation, name, prove)
            for name in cls._verifier_names:
                setattr(aggregation, name, make_verifier(originals[name]))
            yield
        finally:
            for name, original in originals.items():
                setattr(aggregation, name, original)
