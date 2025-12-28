"""
Multisig aggregation helpers bridging leanSpec containers to bindings.

This module wraps the Python bindings exposed by the `leanMultisig-py` project to provide
Multisig signature aggregation + verification.
"""

from __future__ import annotations

from typing import Self, Sequence

from lean_multisig_py import aggregate_signatures as aggregate_signatures_py
from lean_multisig_py import setup_prover, setup_verifier
from lean_multisig_py import verify_aggregated_signatures as verify_aggregated_signatures_py

from lean_spec.subspecs.xmss.containers import PublicKey
from lean_spec.subspecs.xmss.containers import Signature as XmssSignature
from lean_spec.types import Uint64
from lean_spec.types.byte_arrays import ByteListMiB


class MultisigError(RuntimeError):
    """Base exception for multisig aggregation helpers."""


class MultisigAggregationError(MultisigError):
    """Raised when multisig fails to aggregate or verify signatures."""


class MultisigAggregatedSignature(ByteListMiB):
    """Variable-length byte list with a limit of 1048576 bytes."""

    # This function will change for recursive aggregation
    # which might additionally require hints.
    @classmethod
    def aggregate_signatures(
        cls,
        public_keys: Sequence[PublicKey],
        signatures: Sequence[XmssSignature],
        message: bytes,
        epoch: Uint64,
    ) -> Self:
        """
        Aggregate XMSS signatures.

        Args:
            public_keys: Public keys of the signers, one per signature.
            signatures: Individual XMSS signatures to aggregate.
            message: The 32-byte message that was signed.
            epoch: The epoch in which the signatures were created.

        Returns:
            The aggregated signature payload.

        Raises:
            MultisigError: If lean-multisig-py is unavailable or aggregation fails.
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
            return cls(data=aggregated_bytes)
        except Exception as exc:
            raise MultisigAggregationError(f"Multisig aggregation failed: {exc}") from exc

    # This function will change for recursive aggregation verification
    # which might additionally require hints.
    def verify_aggregated_payload(
        self,
        public_keys: Sequence[PublicKey],
        message: bytes,
        epoch: Uint64,
    ) -> None:
        """
        Verify a lean-multisig-py aggregated signature payload.

        Args:
            public_keys: Public keys of the signers, one per original signature.
            payload: MultisigAggregatedSignature of the aggregated signature payload.
            message: The 32-byte message that was signed.
            epoch: The epoch in which the signatures were created.

        Raises:
            MultisigError: If lean-multisig-py is unavailable or verification fails.
        """
        setup_verifier()
        try:
            pub_keys_bytes = [pk.encode_bytes() for pk in public_keys]

            # In test mode, we allow verification of a single zero byte payload.
            # TODO: Remove test mode once leanVM is supports correct signature encoding.
            verify_aggregated_signatures_py(
                pub_keys_bytes,
                message,
                self.encode_bytes(),
                int(epoch),
                test_mode=True,
            )
        except Exception as exc:
            raise MultisigAggregationError(f"Multisig verification failed: {exc}") from exc
