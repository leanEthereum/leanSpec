"""Optional structural capabilities a fork may advertise."""

from typing import ClassVar, Protocol, runtime_checkable

from lean_spec.subspecs.xmss.interface import GeneralizedXmssScheme


@runtime_checkable
class SigScheme(Protocol):
    """Fork advertising a generalized XMSS signature scheme.

    - The runtime check only verifies the attribute is present.
    - The static type contract is enforced by the type checker.
    """

    sig_scheme: ClassVar[GeneralizedXmssScheme]
