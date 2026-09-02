//! Fee-ceiling enforcement: the RPC estimate is scaled exactly as `starknet-rs`
//! would, admitted against the caller's ceiling, and the admitted bounds are
//! pinned on the builder so the signed transaction can never exceed the ceiling.

use krusty_kms_common::fee::{ProposedResourceBounds, ResourceBoundsCeiling};
use krusty_kms_common::{KmsError, Result};
use starknet_rust::accounts::{AccountDeploymentV3, ExecutionV3};
use starknet_rust::core::types::FeeEstimate;

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

/// Pin the bounds admitted from `estimate` on `execution`.
pub(super) fn bound_execution<'a, A>(
    execution: ExecutionV3<'a, A>,
    estimate: &FeeEstimate,
    ceiling: &ResourceBoundsCeiling,
) -> Result<ExecutionV3<'a, A>> {
    let bounds = admit_estimate(estimate, ceiling)?;
    Ok(execution
        .l1_gas(bounds.l1_gas.max_amount)
        .l1_gas_price(bounds.l1_gas.max_price_per_unit)
        .l2_gas(bounds.l2_gas.max_amount)
        .l2_gas_price(bounds.l2_gas.max_price_per_unit)
        .l1_data_gas(bounds.l1_data_gas.max_amount)
        .l1_data_gas_price(bounds.l1_data_gas.max_price_per_unit))
}

/// Pin the bounds admitted from `estimate` on `deployment`.
pub(super) fn bound_deployment<'f, F>(
    deployment: AccountDeploymentV3<'f, F>,
    estimate: &FeeEstimate,
    ceiling: &ResourceBoundsCeiling,
) -> Result<AccountDeploymentV3<'f, F>> {
    let bounds = admit_estimate(estimate, ceiling)?;
    Ok(deployment
        .l1_gas(bounds.l1_gas.max_amount)
        .l1_gas_price(bounds.l1_gas.max_price_per_unit)
        .l2_gas(bounds.l2_gas.max_amount)
        .l2_gas_price(bounds.l2_gas.max_price_per_unit)
        .l1_data_gas(bounds.l1_data_gas.max_amount)
        .l1_data_gas_price(bounds.l1_data_gas.max_price_per_unit))
}

#[cfg(test)]
mod tests;
