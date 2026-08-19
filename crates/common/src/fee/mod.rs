//! Caller-controlled bounds on what a V3 transaction may cost.
//!
//! V3 signatures commit `tip` and all six gas bounds. Left unset they come from
//! the endpoint, and the fee is `(l2_gas_price + tip) * l2_gas_consumed + ...`,
//! so it can pick values that drain the account.

use crate::error::{KmsError, Result};

/// One STRK expressed in FRI. Matches `utils::STRK_DECIMALS`, whose
/// [`fri_to_strk`](crate::utils::fri_to_strk) formats the approval errors below.
pub const ONE_STRK_FRI: u128 = 1_000_000_000_000_000_000;

/// Mirrors starknet-rs, so pinning bounds changes nothing on honest endpoints.
const DEFAULT_ESTIMATE_MULTIPLIER: f64 = 1.5;

/// The six `FeeEstimate` scalars, kept free of any Starknet type.
#[derive(Debug, Clone, Copy)]
pub struct FeeEstimateInput {
    pub l1_gas_consumed: u64,
    pub l1_gas_price: u128,
    pub l2_gas_consumed: u64,
    pub l2_gas_price: u128,
    pub l1_data_gas_consumed: u64,
    pub l1_data_gas_price: u128,
}

/// Bounds that passed the caller's approval check.
///
/// `#[non_exhaustive]` stops another crate constructing one from scratch, but
/// the fields stay public and readable, so it is a value type rather than a
/// capability token: a caller can still copy one and edit it. That is by
/// design — approval is the caller's own policy, and one who edits past it
/// could equally have raised `max_fee_fri`. What it defends against is the
/// *endpoint*, never the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedFeeBounds {
    pub l1_gas: u64,
    pub l1_gas_price: u128,
    pub l2_gas: u64,
    pub l2_gas_price: u128,
    pub l1_data_gas: u64,
    pub l1_data_gas_price: u128,
    pub tip: u64,
}

impl ResolvedFeeBounds {
    /// Total cost in FRI if every resource is consumed at its max price, plus
    /// the tip per unit of L2 gas. Named to stay distinct from
    /// [`FeeBounds::max_fee_fri`], the user approval this is compared against.
    pub fn total_fri(&self) -> Option<u128> {
        let l1 = (self.l1_gas as u128).checked_mul(self.l1_gas_price)?;
        let l2 = (self.l2_gas as u128).checked_mul(self.l2_gas_price)?;
        let data = (self.l1_data_gas as u128).checked_mul(self.l1_data_gas_price)?;
        let tip = (self.tip as u128).checked_mul(self.l2_gas as u128)?;
        l1.checked_add(l2)?.checked_add(data)?.checked_add(tip)
    }
}

/// What a caller is willing to spend. The default pins the tip to zero but
/// approves no fee; setting all six gas fields skips the estimate entirely.
///
/// Deliberately *not* `#[non_exhaustive]`, unlike [`ResolvedFeeBounds`]: that
/// attribute blocks functional-update syntax from other crates too, so
/// `FeeBounds { max_fee_fri: Some(x), ..Default::default() }` would stop
/// compiling and every field would need a builder method.
/// The cost is that a future field is a breaking change, which
/// `cargo-semver-checks` will catch and turn into a version bump.
#[derive(Debug, Clone, Copy)]
pub struct FeeBounds {
    /// Per-L2-gas-unit tip, never taken from the endpoint's block median.
    pub tip: u64,
    /// User-approved ceiling in FRI. `None` estimates but never signs, allowing
    /// the caller to show the resolved bound and ask for approval.
    pub max_fee_fri: Option<u128>,
    /// `None` means "take it from the estimate and scale".
    pub l1_gas: Option<u64>,
    pub l1_gas_price: Option<u128>,
    pub l2_gas: Option<u64>,
    pub l2_gas_price: Option<u128>,
    pub l1_data_gas: Option<u64>,
    pub l1_data_gas_price: Option<u128>,
    /// Headroom applied to estimated amounts and prices.
    pub gas_multiplier: f64,
    pub price_multiplier: f64,
}

impl Default for FeeBounds {
    fn default() -> Self {
        Self {
            tip: 0,
            max_fee_fri: None,
            l1_gas: None,
            l1_gas_price: None,
            l2_gas: None,
            l2_gas_price: None,
            l1_data_gas: None,
            l1_data_gas_price: None,
            gas_multiplier: DEFAULT_ESTIMATE_MULTIPLIER,
            price_multiplier: DEFAULT_ESTIMATE_MULTIPLIER,
        }
    }
}

impl FeeBounds {
    /// Approve signing up to `max_fee_fri` after the endpoint's estimate is
    /// scaled and all resource bounds are resolved.
    #[must_use]
    pub fn with_max_fee_fri(mut self, max_fee_fri: u128) -> Self {
        self.max_fee_fri = Some(max_fee_fri);
        self
    }

    /// `Some` when every gas field is explicit, so no estimate is needed.
    pub fn explicit(&self) -> Option<Result<ResolvedFeeBounds>> {
        let l1_gas = self.l1_gas?;
        let l1_gas_price = self.l1_gas_price?;
        let l2_gas = self.l2_gas?;
        let l2_gas_price = self.l2_gas_price?;
        let l1_data_gas = self.l1_data_gas?;
        let l1_data_gas_price = self.l1_data_gas_price?;

        Some(self.check_multipliers().and_then(|()| {
            self.finish(
                l1_gas,
                l1_gas_price,
                l2_gas,
                l2_gas_price,
                l1_data_gas,
                l1_data_gas_price,
            )
        }))
    }

    /// Both multipliers, checked even when this call will not apply them: one
    /// left unused by a particular set of explicit fields is still a
    /// misconfiguration, and accepting it here but rejecting it in `resolve`
    /// would make the same value valid or invalid depending on the caller.
    fn check_multipliers(&self) -> Result<()> {
        check_multiplier("gas_multiplier", self.gas_multiplier)?;
        check_multiplier("price_multiplier", self.price_multiplier)
    }

    /// Explicit fields win; the rest are the estimate scaled. Signing requires
    /// an approved [`max_fee_fri`](Self::max_fee_fri) at least this large.
    pub fn resolve(&self, estimate: &FeeEstimateInput) -> Result<ResolvedFeeBounds> {
        self.check_multipliers()?;

        let amount = |explicit: Option<u64>, estimated: u64| -> Result<u64> {
            match explicit {
                Some(v) => Ok(v),
                None => scale_u64(estimated, self.gas_multiplier),
            }
        };
        let price = |explicit: Option<u128>, estimated: u128| -> Result<u128> {
            match explicit {
                Some(v) => Ok(v),
                None => scale_u128(estimated, self.price_multiplier),
            }
        };

        self.finish(
            amount(self.l1_gas, estimate.l1_gas_consumed)?,
            price(self.l1_gas_price, estimate.l1_gas_price)?,
            amount(self.l2_gas, estimate.l2_gas_consumed)?,
            price(self.l2_gas_price, estimate.l2_gas_price)?,
            amount(self.l1_data_gas, estimate.l1_data_gas_consumed)?,
            price(self.l1_data_gas_price, estimate.l1_data_gas_price)?,
        )
    }

    /// The single gate every resolved value passes through.
    fn finish(
        &self,
        l1_gas: u64,
        l1_gas_price: u128,
        l2_gas: u64,
        l2_gas_price: u128,
        l1_data_gas: u64,
        l1_data_gas_price: u128,
    ) -> Result<ResolvedFeeBounds> {
        let resolved = ResolvedFeeBounds {
            l1_gas,
            l1_gas_price,
            l2_gas,
            l2_gas_price,
            l1_data_gas,
            l1_data_gas_price,
            tip: self.tip,
        };

        let total = resolved.total_fri().ok_or_else(|| {
            KmsError::TransactionError(
                "fee bounds exceeded: resolved fee overflows u128 FRI".to_string(),
            )
        })?;

        let Some(max_fee_fri) = self.max_fee_fri else {
            return Err(KmsError::TransactionError(format!(
                "fee approval required: resolved maximum is {total} FRI ({} STRK); ask the \
                 user, then resubmit with FeeBounds::with_max_fee_fri(user_approved_fri)",
                crate::utils::fri_to_strk(total),
            )));
        };

        if total > max_fee_fri {
            return Err(KmsError::TransactionError(format!(
                "fee approval required: resolved maximum {total} FRI ({} STRK) exceeds the \
                 approved {max_fee_fri} FRI ({} STRK); ask the user before raising \
                 FeeBounds::max_fee_fri",
                crate::utils::fri_to_strk(total),
                crate::utils::fri_to_strk(max_fee_fri)
            )));
        }

        Ok(resolved)
    }
}

/// Scale an estimate, rejecting a product too large for the target type.
///
/// The approval check would miss it: casts saturate, and a saturated amount paired
/// with a zero price adds nothing to the total.
fn scale_u64(value: u64, multiplier: f64) -> Result<u64> {
    let scaled = value as f64 * multiplier;
    // `>=`, not `>`: `u64::MAX as f64` rounds *up* to 2^64, so a product
    // landing exactly there would pass `>` and then saturate.
    if scaled >= u64::MAX as f64 {
        return Err(overflowed("gas amount", scaled));
    }
    Ok(scaled as u64)
}

fn scale_u128(value: u128, multiplier: f64) -> Result<u128> {
    let scaled = value as f64 * multiplier;
    if scaled >= u128::MAX as f64 {
        return Err(overflowed("gas price", scaled));
    }
    Ok(scaled as u128)
}

fn overflowed(what: &str, scaled: f64) -> KmsError {
    KmsError::TransactionError(format!(
        "fee bounds exceeded: scaled {what} {scaled:e} overflows its bound"
    ))
}

fn check_multiplier(name: &str, multiplier: f64) -> Result<()> {
    if !multiplier.is_finite() || multiplier < 1.0 {
        return Err(KmsError::TransactionError(format!(
            "invalid fee estimate {name} {multiplier} (must be finite and >= 1.0)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
