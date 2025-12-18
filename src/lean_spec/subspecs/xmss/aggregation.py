"""
lean-multisig aggregation helpers bridging leanSpec containers to native bindings.

This module wraps the Python bindings exposed by the `lean-multisig` project to provide
XMSS signature aggregation + verification.

The aggregated signatures are stored as raw payload bytes produced by
`lean_multisig.aggregate_signatures`.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Sequence

from lean_spec.subspecs.xmss.containers import PublicKey, Signature
from lean_spec.types import Uint64


class LeanMultisigError(RuntimeError):
    """Base exception for lean-multisig aggregation helpers."""


class LeanMultisigUnavailableError(LeanMultisigError):
    """Raised when the lean-multisig Python bindings cannot be imported."""


class LeanMultisigAggregationError(LeanMultisigError):
    """Raised when lean-multisig fails to aggregate or verify signatures."""


@lru_cache(maxsize=1)
def _import_lean_multisig():
    try:
        import lean_multisig  # type: ignore
    except ModuleNotFoundError as exc:  # pragma: no cover - import is environment-specific
        raise LeanMultisigUnavailableError(
            "lean-multisig bindings are required. Install them with `uv pip install lean-multisig` "
            "(or your local editable install) from the leanSpec repository."
        ) from exc
    return lean_multisig


@lru_cache(maxsize=1)
def _ensure_prover_setup() -> None:
    """Run the (expensive) prover setup routine exactly once."""
    _import_lean_multisig().setup_prover()


@lru_cache(maxsize=1)
def _ensure_verifier_setup() -> None:
    """Run the verifier setup routine exactly once."""
    _import_lean_multisig().setup_verifier()


def _coerce_epoch(epoch: int | Uint64) -> int:
    value = int(epoch)
    if value < 0 or value >= 2**32:
        raise ValueError("epoch must fit in uint32 for lean-multisig aggregation")
    return value


def aggregate_signatures(
    public_keys: Sequence[PublicKey],
    signatures: Sequence[Signature],
    message: bytes,
    epoch: int | Uint64,
) -> bytes:
    """
    Aggregate XMSS signatures using lean-multisig.

    Args:
        public_keys: Public keys of the signers, one per signature.
        signatures: Individual XMSS signatures to aggregate.
        message: The 32-byte message that was signed.
        epoch: The epoch in which the signatures were created.

    Returns:
        Raw bytes of the aggregated signature payload.

    Raises:
        LeanMultisigError: If lean-multisig is unavailable or aggregation fails.
    """
    lean_multisig = _import_lean_multisig()
    _ensure_prover_setup()
    try:
        # `lean_multisig` expects serialized keys/signatures as raw bytes.
        # We use leanSpec's SSZ encoding for these containers.
        pub_keys_bytes = [pk.encode_bytes() for pk in public_keys]
        sig_bytes = [sig.encode_bytes() for sig in signatures]

        aggregated_bytes = lean_multisig.aggregate_signatures(
            pub_keys_bytes,
            sig_bytes,
            message,
            _coerce_epoch(epoch),
        )
        return aggregated_bytes
    except Exception as exc:
        raise LeanMultisigAggregationError(f"lean-multisig aggregation failed: {exc}") from exc


def verify_aggregated_payload(
    public_keys: Sequence[PublicKey],
    payload: bytes,
    message: bytes,
    epoch: int | Uint64,
) -> None:
    """
    Verify a lean-multisig aggregated signature payload.

    Args:
        public_keys: Public keys of the signers, one per original signature.
        payload: Raw bytes of the aggregated signature payload.
        message: The 32-byte message that was signed.
        epoch: The epoch in which the signatures were created.

    Raises:
        LeanMultisigError: If lean-multisig is unavailable or verification fails.
    """
    lean_multisig = _import_lean_multisig()
    _ensure_verifier_setup()
    try:
        pub_keys_bytes = [pk.encode_bytes() for pk in public_keys]
        lean_multisig.verify_aggregated_signatures(
            pub_keys_bytes,
            message,
            payload,
            _coerce_epoch(epoch),
        )
    except Exception as exc:
        raise LeanMultisigAggregationError(f"lean-multisig verification failed: {exc}") from exc
