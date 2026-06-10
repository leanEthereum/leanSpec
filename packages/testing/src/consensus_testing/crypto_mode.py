"""
Mock the Rust aggregation prover at the FFI boundary, from the test layer.

Most vectors do not test proofs, yet building one costs a recursive SNARK merge.

Mocking lets the fast scheme skip that work while leaving the spec untouched.

Vectors whose purpose is proof validity opt back in with the real_crypto marker.
"""

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

    @staticmethod
    def _placeholder_proof(positional_args: tuple[object, ...]) -> bytes:
        """
        Build a deterministic placeholder proof bound to a call's inputs.

        Length framing keeps distinct inputs distinct.

        So two different blocks never share proof bytes by accident.
        """
        digest = hashlib.sha256()
        stack: list[object] = [positional_args]
        while stack:
            value = stack.pop()
            if isinstance(value, bool):
                digest.update(b"b\x01" if value else b"b\x00")
            elif isinstance(value, int):
                encoded = str(value).encode()
                digest.update(b"i" + len(encoded).to_bytes(8, "big") + encoded)
            elif isinstance(value, bytes):
                digest.update(b"y" + len(value).to_bytes(8, "big") + value)
            elif isinstance(value, (list, tuple)):
                digest.update(b"s" + len(value).to_bytes(8, "big"))
                stack.extend(reversed(value))
            elif value is None:
                digest.update(b"n")
            else:
                raise TypeError(f"unmockable prover argument of type {type(value).__name__}")
        return MOCK_PROOF_PREFIX + digest.digest()

    @classmethod
    @contextmanager
    def mocked(cls) -> Iterator[None]:
        """
        Swap the Rust prover bindings on the spec module for in-process stubs.

        - Provers return a placeholder proof;
        - Verifiers accept that placeholder.

        The spec's own structural checks still run; only the Rust call is skipped.
        A real proof reaching the mocked verifier falls through to the real one.
        """
        originals = {
            name: getattr(aggregation, name) for name in (*cls._prover_names, *cls._verifier_names)
        }

        def prove(*positional_args: object, **_keyword_args: object) -> tuple[None, bytes]:
            return None, cls._placeholder_proof(positional_args)

        def make_verifier(real_verifier: Callable[..., None]) -> Callable[..., None]:
            def verify(*positional_args: object, **keyword_args: object) -> None:
                carries_placeholder = any(
                    isinstance(argument, bytes) and argument.startswith(MOCK_PROOF_PREFIX)
                    for argument in positional_args
                )
                if carries_placeholder:
                    return None
                return real_verifier(*positional_args, **keyword_args)

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
