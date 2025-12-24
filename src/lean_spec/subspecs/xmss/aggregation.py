"""
lean-multisig aggregation helpers bridging leanSpec containers to bindings.

This module wraps the Python bindings exposed by the `leanMultisig-py` project to provide
XMSS signature aggregation + verification.
"""

from __future__ import annotations

from typing import Sequence

from lean_multisig_py import aggregate_signatures as aggregate_signatures_py
from lean_multisig_py import setup_prover, setup_verifier
from lean_multisig_py import verify_aggregated_signatures as verify_aggregated_signatures_py

from lean_spec.subspecs.xmss.containers import PublicKey
from lean_spec.subspecs.xmss.containers import Signature as XmssSignature
from lean_spec.types import Uint64


class LeanMultisigError(RuntimeError):
    """Base exception for lean-multisig aggregation helpers."""


class LeanMultisigAggregationError(LeanMultisigError):
    """Raised when lean-multisig fails to aggregate or verify signatures."""


# This function will change for recursive aggregation
# which might additionally require hints.
def aggregate_signatures(
    public_keys: Sequence[PublicKey],
    signatures: Sequence[XmssSignature],
    message: bytes,
    epoch: Uint64,
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
    setup_prover()
    try:
        pub_keys_bytes = [pk.encode_bytes() for pk in public_keys]
        sig_bytes = [sig.encode_bytes() for sig in signatures]

        # In test mode, we return a single zero byte payload.
        # TODO: Remove test mode once leanVM is supports correct signature encoding.
        aggregated_bytes = aggregate_signatures_py(
            pub_keys_bytes,
            sig_bytes,
            message,
            epoch,
            test_mode=True,
        )
        return aggregated_bytes
    except Exception as exc:
        raise LeanMultisigAggregationError(f"lean-multisig aggregation failed: {exc}") from exc


# This function will change for recursive aggregation verification
# which might additionally require hints.
def verify_aggregated_payload(
    public_keys: Sequence[PublicKey],
    payload: bytes,
    message: bytes,
    epoch: Uint64,
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
    setup_verifier()
    try:
        pub_keys_bytes = [pk.encode_bytes() for pk in public_keys]

        # In test mode, we allow verification of a single zero byte payload.
        # TODO: Remove test mode once leanVM is supports correct signature encoding.
        verify_aggregated_signatures_py(
            pub_keys_bytes,
            message,
            payload,
            epoch,
            test_mode=True,
        )
    except Exception as exc:
        raise LeanMultisigAggregationError(f"lean-multisig verification failed: {exc}") from exc
