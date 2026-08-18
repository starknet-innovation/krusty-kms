//! Caller-controlled bounds on what a V3 transaction may cost.
//!
//! V3 signatures commit `tip` and all six gas bounds. Left unset they come from
//! the endpoint, and the fee is `(l2_gas_price + tip) * l2_gas_consumed + ...`,
//! so it can pick values that drain the account.

use crate::error::{KmsError, Result};

/// One STRK expressed in FRI (10^-18 STRK).
pub const ONE_STRK_FRI: u128 = 1_000_000_000_000_000_000;

/// Ceiling applied when the caller sets none. Real fees sit far below this.
pub const DEFAULT_MAX_FEE_FRI: u128 = ONE_STRK_FRI;

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

/// Bounds that passed the ceiling check — `#[non_exhaustive]` is what makes
/// holding one proof of that, since no other crate can assemble one.
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
    /// Max cost in FRI: each resource at its max price, plus tip per L2 gas.
    pub fn max_fee_fri(&self) -> Option<u128> {
        let l1 = (self.l1_gas as u128).checked_mul(self.l1_gas_price)?;
        let l2 = (self.l2_gas as u128).checked_mul(self.l2_gas_price)?;
        let data = (self.l1_data_gas as u128).checked_mul(self.l1_data_gas_price)?;
        let tip = (self.tip as u128).checked_mul(self.l2_gas as u128)?;
        l1.checked_add(l2)?.checked_add(data)?.checked_add(tip)
    }
}

/// What a caller is willing to spend. The default pins the tip to zero and
/// caps the total; setting all six gas fields skips the estimate entirely.
#[derive(Debug, Clone, Copy)]
pub struct FeeBounds {
    /// Per-L2-gas-unit tip, never taken from the endpoint's block median.
    pub tip: u64,
    /// Hard ceiling in FRI; signing is refused above it.
    pub max_fee_fri: u128,
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
            max_fee_fri: DEFAULT_MAX_FEE_FRI,
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
    /// `Some` when every gas field is explicit, so no estimate is needed.
    pub fn explicit(&self) -> Option<Result<ResolvedFeeBounds>> {
        Some(self.finish(
            self.l1_gas?,
            self.l1_gas_price?,
            self.l2_gas?,
            self.l2_gas_price?,
            self.l1_data_gas?,
            self.l1_data_gas_price?,
        ))
    }

    /// Explicit fields win; the rest are the estimate scaled. Errors above
    /// [`max_fee_fri`](Self::max_fee_fri).
    pub fn resolve(&self, estimate: &FeeEstimateInput) -> Result<ResolvedFeeBounds> {
        // Up front, not inside the scalers: a multiplier left unused by this
        // particular set of explicit fields is still a misconfiguration.
        check_multiplier("gas_multiplier", self.gas_multiplier)?;
        check_multiplier("price_multiplier", self.price_multiplier)?;

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

        let total = resolved.max_fee_fri().ok_or_else(|| {
            KmsError::TransactionError(
                "fee bounds exceeded: resolved fee overflows u128 FRI".to_string(),
            )
        })?;

        if total > self.max_fee_fri {
            return Err(KmsError::TransactionError(format!(
                "fee bounds exceeded: resolved max fee {total} FRI exceeds ceiling {} FRI \
                 (raise FeeBounds::max_fee_fri if this is expected)",
                self.max_fee_fri
            )));
        }

        Ok(resolved)
    }
}

/// Scale an estimate, rejecting a product too large for the target type.
///
/// The ceiling would miss it: casts saturate, and a saturated amount paired
/// with a zero price adds nothing to the total.
fn scale_u64(value: u64, multiplier: f64) -> Result<u64> {
    let scaled = value as f64 * multiplier;
    if scaled > u64::MAX as f64 {
        return Err(overflowed("gas amount", scaled));
    }
    Ok(scaled as u64)
}

fn scale_u128(value: u128, multiplier: f64) -> Result<u128> {
    let scaled = value as f64 * multiplier;
    if scaled > u128::MAX as f64 {
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
