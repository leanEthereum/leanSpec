"""
Generalized XMSS hash-based signature scheme.

References:
    - Hash-Based Multi-Signatures for Post-Quantum Ethereum.
      https://eprint.iacr.org/2025/055.pdf
    - Aborting Random Oracles, How to Build Them, How to Use Them.
      https://eprint.iacr.org/2026/016.pdf
"""

from lean_multisig_py import setup_prover

# Break the import cycle between the signature and fork containers.
# The signature containers need the fork slot type, while the fork
# aggregation containers import the signature containers back.
# Loading the forks package first lets the cycle resolve from any entry point.
import lean_spec.spec.forks  # noqa: F401
from lean_spec.config import LEAN_ENV
from lean_spec.spec.crypto.xmss.containers import PublicKey, SecretKey
from lean_spec.spec.crypto.xmss.interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme

# Side effect: configures the Rust prover for the lifetime of the process.
# One call covers every aggregation, verification, split, and merge.
# Per-call invocations then default to the mode established here.
setup_prover(mode=LEAN_ENV)


__all__ = [
    "GeneralizedXmssScheme",
    "PublicKey",
    "SecretKey",
    "TARGET_SIGNATURE_SCHEME",
]
