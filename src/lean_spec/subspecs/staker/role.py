"""This defines the roles a Staker can activate for itself."""

from typing import List

from lean_spec.subspecs.staker import DEVNET_STAKER_CONFIG
from lean_spec.types import Epoch, Gwei, StrictBaseModel, Uint64


class AttesterRole(StrictBaseModel):
    """Parameters for the Attester Role."""

    activation_eligibility_epoch: Epoch
    """The epoch in which the role enters the activation queue."""

    activation_epoch: Epoch
    """The epoch in which the role becomes active."""

    exit_epoch: Epoch
    """The epoch in which the delegated balance stops participating in the
    protocol but remains accountable."""

    withdrawable_epoch: Epoch
    """The epoch in which the delegated balance is no longer held
    accountable and is credited to the delegator."""

    is_active: bool
    """Determines if the role is active or not."""

    balance: Gwei
    """The actual balance of the staker's role."""

    slashed: bool
    """Determines if the staker has been slashed for this role."""

    staker_quota: Uint64
    """The quota of the staker's role in the delegation."""

    delegations_quotas: List[Uint64,
    DEVNET_STAKER_CONFIG.delegations_registry_limit]
    """The quotas of each delegated balance for this role. This list is
    parallel with the stakers list from the state."""

    delegated_balances: List[Uint64,
    DEVNET_STAKER_CONFIG.delegations_registry_limit]
    """The delegated balances for each staker. This list is parallel with
    the stakers list from the state."""

    total_delegated_balance: Gwei
    """This is the sum of every value in `delegated_balances` and is used
    for performance optimisation purposes."""


class IncluderRole(StrictBaseModel):
    """Parameters for the Includer Role."""

    is_active: bool
    """Determines if the role is active or not."""

    balance: Gwei
    """The actual balance of the staker's role."""

    staker_quota: Uint64
    """The quota of the staker's role in the delegation."""

    delegations_quotas: List[Uint64,
    DEVNET_STAKER_CONFIG.delegations_registry_limit]
    """The quotas of each delegated balance for this role. This list is
    parallel with the stakers list from the state."""

    delegated_balances: List[Uint64,
    DEVNET_STAKER_CONFIG.delegations_registry_limit]
    """The delegated balances for each staker. This list is parallel with
    the stakers list from the state."""

    total_delegated_balance: Gwei
    """This is the sum of every value in `delegated_balances` and is used
    for performance optimisation purposes."""


class ProposerRole(StrictBaseModel):
    """Parameters for the Proposer Role."""

    activation_eligibility_epoch: Epoch
    """The epoch in which the role enters the activation queue."""

    activation_epoch: Epoch
    """The epoch in which the role becomes active."""

    exit_epoch: Epoch
    """The epoch in which the delegated balance stops participating in the
    protocol but remains accountable."""

    withdrawable_epoch: Epoch
    """The epoch in which the delegated balance is no longer held
    accountable and is credited to the delegator."""

    is_active: bool
    """Determines if the role is active or not."""

    balance: Gwei
    """The actual balance of the staker's role."""

    slashed: bool
    """Determines if the staker has been slashed for this role."""

    staker_quota: Uint64
    """The quota of the staker's role in the delegation."""

    delegations_quotas: List[Uint64,
    DEVNET_STAKER_CONFIG.delegations_registry_limit]
    """The quotas of each delegated balance for this role. This list is
    parallel with the stakers list from the state."""

    delegated_balances: List[Uint64,
    DEVNET_STAKER_CONFIG.delegations_registry_limit]
    """The delegated balances for each staker. This list is parallel with
    the stakers list from the state."""

    total_delegated_balance: Gwei
    """This is the sum of every value in `delegated_balances` and is used
    for performance optimisation purposes."""
