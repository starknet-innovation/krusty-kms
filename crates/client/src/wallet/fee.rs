//! Fee-ceiling enforcement: the RPC estimate is scaled exactly as `starknet-rs`
//! would, admitted against the caller's ceiling, and the admitted bounds are
//! pinned on the builder so the signed transaction can never exceed the ceiling.
//!
//! The V3 tip is pinned on every path, with or without a ceiling. Left unset,
//! `starknet-rs` resolves it in `prepare` by fetching the pending block from
//! the RPC and taking the median tip, and a tip is paid in full per unit of L2
//! gas, so an unset tip hands the RPC an unbounded fee term.

use krusty_kms_common::fee::{ProposedResourceBounds, ResourceBoundsCeiling, DEFAULT_TIP};
use krusty_kms_common::{KmsError, Result};
use starknet_rust_accounts::{AccountDeploymentV3, ExecutionV3};
use starknet_rust_core::types::FeeEstimate;

/// Scale `estimate` with the `starknet-rs` multipliers and admit it against `ceiling`.
pub(super) fn admit_estimate(
    estimate: &FeeEstimate,
    ceiling: &ResourceBoundsCeiling,
) -> Result<ProposedResourceBounds> {
    ceiling
        .admit_estimate(
            (estimate.l1_gas_consumed, estimate.l1_gas_price),
            (estimate.l2_gas_consumed, estimate.l2_gas_price),
            (estimate.l1_data_gas_consumed, estimate.l1_data_gas_price),
        )
        .map_err(|error| KmsError::FeeEstimationFailed(format!("fee ceiling: {error}")))
}

/// Pin the tip on `execution`: the ceiling's `max_tip`, or [`DEFAULT_TIP`]
/// without a ceiling. Either way `starknet-rs` never asks the RPC for one.
pub(super) fn pin_execution_tip<'a, A>(
    execution: ExecutionV3<'a, A>,
    ceiling: Option<&ResourceBoundsCeiling>,
) -> ExecutionV3<'a, A> {
    execution.tip(ceiling.map_or(DEFAULT_TIP, |ceiling| ceiling.max_tip))
}

/// Pin the tip on `deployment`: the ceiling's `max_tip`, or [`DEFAULT_TIP`]
/// without a ceiling. Either way `starknet-rs` never asks the RPC for one.
pub(super) fn pin_deployment_tip<'f, F>(
    deployment: AccountDeploymentV3<'f, F>,
    ceiling: Option<&ResourceBoundsCeiling>,
) -> AccountDeploymentV3<'f, F> {
    deployment.tip(ceiling.map_or(DEFAULT_TIP, |ceiling| ceiling.max_tip))
}

/// Pin the bounds admitted from `estimate`, and the ceiling's tip, on `execution`.
pub(super) fn bound_execution<'a, A>(
    execution: ExecutionV3<'a, A>,
    estimate: &FeeEstimate,
    ceiling: &ResourceBoundsCeiling,
) -> Result<ExecutionV3<'a, A>> {
    let bounds = admit_estimate(estimate, ceiling)?;
    Ok(execution
        .tip(ceiling.max_tip)
        .l1_gas(bounds.l1_gas.max_amount)
        .l1_gas_price(bounds.l1_gas.max_price_per_unit)
        .l2_gas(bounds.l2_gas.max_amount)
        .l2_gas_price(bounds.l2_gas.max_price_per_unit)
        .l1_data_gas(bounds.l1_data_gas.max_amount)
        .l1_data_gas_price(bounds.l1_data_gas.max_price_per_unit))
}

/// Pin the bounds admitted from `estimate`, and the ceiling's tip, on `deployment`.
pub(super) fn bound_deployment<'f, F>(
    deployment: AccountDeploymentV3<'f, F>,
    estimate: &FeeEstimate,
    ceiling: &ResourceBoundsCeiling,
) -> Result<AccountDeploymentV3<'f, F>> {
    let bounds = admit_estimate(estimate, ceiling)?;
    Ok(deployment
        .tip(ceiling.max_tip)
        .l1_gas(bounds.l1_gas.max_amount)
        .l1_gas_price(bounds.l1_gas.max_price_per_unit)
        .l2_gas(bounds.l2_gas.max_amount)
        .l2_gas_price(bounds.l2_gas.max_price_per_unit)
        .l1_data_gas(bounds.l1_data_gas.max_amount)
        .l1_data_gas_price(bounds.l1_data_gas.max_price_per_unit))
}

#[cfg(test)]
mod tests;
