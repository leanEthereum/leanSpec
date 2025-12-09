"""Signature scheme helpers for consensus layer testing."""

from lean_spec.subspecs.xmss.interface import (
    PROD_SIGNATURE_SCHEME,
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
)

SIGNATURE_SCHEMES = {
    "test": TEST_SIGNATURE_SCHEME,
    "prod": PROD_SIGNATURE_SCHEME,
}
"""
Mapping from short name to scheme objects. This mapping is useful for:
- The CLI argument for choosing the signature scheme to generate
- Deriving the file name for the cached keys
- Caching key managers in test fixtures
"""

CURRENT_SIGNATURE_SCHEME: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME
"""
Current signature scheme for the session.

This is set once at session start via CLI and never changes during the session.
"""


def set_current_signature_scheme(scheme: GeneralizedXmssScheme) -> None:
    """
    Set the current signature scheme for the test session.

    Args:
        scheme: The signature scheme to be set.
    """
    global CURRENT_SIGNATURE_SCHEME
    CURRENT_SIGNATURE_SCHEME = scheme


def get_current_signature_scheme() -> GeneralizedXmssScheme:
    """
    Get the current signature scheme name.

    Returns:
        The current signature scheme for the test session.
    """
    return CURRENT_SIGNATURE_SCHEME


def get_name_by_signature_scheme(scheme: GeneralizedXmssScheme) -> str:
    """
    Get the scheme name for a given scheme object.

    Args:
        scheme: The XMSS signature scheme.

    Returns:
        The scheme name string (e.g. "test" or "prod").

    Raises:
        ValueError: If the scheme is not recognized.
    """
    for scheme_name, scheme_obj in SIGNATURE_SCHEMES.items():
        if scheme_obj is scheme:
            return scheme_name
    raise ValueError(f"Unknown scheme: {scheme}")
