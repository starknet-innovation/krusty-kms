//! Caller-supplied ceilings for Starknet V3 resource bounds.
//!
//! RPC fee estimates are untrusted input: without a ceiling a wallet signs
//! whatever bounds the estimate implies. A [`ResourceBoundsCeiling`] admits
//! bounds derived from an estimate only when every amount and price is at or
//! below the ceiling; it never widens or clamps, and degenerate (zero)
//! ceilings are rejected before any comparison. No I/O happens here.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Multiplier `starknet-rs` applies to estimated gas amounts and prices before signing.
pub const ESTIMATE_MULTIPLIER: f64 = 1.5;

/// Dimension names, in the order used by every `[MaxBound; 3]` below.
const DIMENSIONS: [&str; 3] = ["l1_gas", "l2_gas", "l1_data_gas"];

/// Upper bound for one dimension: at most `max_amount` units at `max_price_per_unit` fri each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaxBound {
    pub max_amount: u64,
    pub max_price_per_unit: u128,
}

impl MaxBound {
    /// Scale a raw RPC estimate exactly as `starknet-rs` does before signing.
    pub fn from_estimate(consumed: u64, price_per_unit: u128) -> Result<Self, FeeCeilingError> {
        let price =
            u64::try_from(price_per_unit).map_err(|_| FeeCeilingError::EstimateOutOfRange)?;
        Ok(Self {
            max_amount: (consumed as f64 * ESTIMATE_MULTIPLIER) as u64,
            max_price_per_unit: (price as f64 * ESTIMATE_MULTIPLIER) as u128,
        })
    }

    const fn fields(self) -> [(&'static str, u128); 2] {
        [
            ("max_amount", self.max_amount as u128),
            ("max_price_per_unit", self.max_price_per_unit),
        ]
    }
}

/// Bounds a wallet is about to sign, one [`MaxBound`] per dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedResourceBounds {
    pub l1_gas: MaxBound,
    pub l2_gas: MaxBound,
    pub l1_data_gas: MaxBound,
}

impl ProposedResourceBounds {
    /// Scale `(consumed, price_per_unit)` estimates for every dimension.
    pub fn from_estimate(
        l1_gas: (u64, u128),
        l2_gas: (u64, u128),
        l1_data_gas: (u64, u128),
    ) -> Result<Self, FeeCeilingError> {
        Ok(Self {
            l1_gas: MaxBound::from_estimate(l1_gas.0, l1_gas.1)?,
            l2_gas: MaxBound::from_estimate(l2_gas.0, l2_gas.1)?,
            l1_data_gas: MaxBound::from_estimate(l1_data_gas.0, l1_data_gas.1)?,
        })
    }

    const fn bounds(&self) -> [MaxBound; 3] {
        [self.l1_gas, self.l2_gas, self.l1_data_gas]
    }
}

/// Caller-supplied ceiling on the resource bounds a wallet may sign.
///
/// Invariant: every field is non-zero. [`Self::new`] enforces it and
/// [`Self::admit`] re-checks it, so a deserialized value cannot bypass validation.
/// The worst-case fee a ceiling permits is `Σ max_amount × max_price_per_unit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResourceBoundsCeiling {
    pub l1_gas: MaxBound,
    pub l2_gas: MaxBound,
    pub l1_data_gas: MaxBound,
}

impl ResourceBoundsCeiling {
    /// Construct and validate a ceiling.
    pub fn new(
        l1_gas: MaxBound,
        l2_gas: MaxBound,
        l1_data_gas: MaxBound,
    ) -> Result<Self, FeeCeilingError> {
        let ceiling = Self {
            l1_gas,
            l2_gas,
            l1_data_gas,
        };
        ceiling.validate()?;
        Ok(ceiling)
    }

    /// Reject degenerate ceilings: a zero field can never admit a live estimate.
    pub fn validate(&self) -> Result<(), FeeCeilingError> {
        for (dimension, bound) in DIMENSIONS.into_iter().zip(self.bounds()) {
            if let Some((field, _)) = bound.fields().into_iter().find(|(_, value)| *value == 0) {
                return Err(FeeCeilingError::ZeroCeiling { dimension, field });
            }
        }
        Ok(())
    }

    /// Admit `proposed` only if every field is at or below this ceiling; the
    /// first violation is reported and nothing is clamped.
    pub fn admit(&self, proposed: &ProposedResourceBounds) -> Result<(), FeeCeilingError> {
        self.validate()?;
        let dimensions = DIMENSIONS
            .into_iter()
            .zip(self.bounds())
            .zip(proposed.bounds());
        for ((dimension, ceiling), proposed) in dimensions {
            for ((field, ceiling), (_, proposed)) in
                ceiling.fields().into_iter().zip(proposed.fields())
            {
                if proposed > ceiling {
                    return Err(FeeCeilingError::Exceeded {
                        dimension,
                        field,
                        proposed,
                        ceiling,
                    });
                }
            }
        }
        Ok(())
    }

    /// Scale a raw estimate and admit it in one step, returning the bounds that may be signed.
    pub fn admit_estimate(
        &self,
        l1_gas: (u64, u128),
        l2_gas: (u64, u128),
        l1_data_gas: (u64, u128),
    ) -> Result<ProposedResourceBounds, FeeCeilingError> {
        let proposed = ProposedResourceBounds::from_estimate(l1_gas, l2_gas, l1_data_gas)?;
        self.admit(&proposed)?;
        Ok(proposed)
    }

    const fn bounds(&self) -> [MaxBound; 3] {
        [self.l1_gas, self.l2_gas, self.l1_data_gas]
    }
}

/// Why a ceiling is invalid, or why it rejected a proposal.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeeCeilingError {
    #[error("fee ceiling {dimension}.{field} must be greater than zero")]
    ZeroCeiling {
        dimension: &'static str,
        field: &'static str,
    },
    #[error("fee estimate price does not fit the signable range")]
    EstimateOutOfRange,
    #[error("proposed {dimension}.{field} {proposed} exceeds fee ceiling {ceiling}")]
    Exceeded {
        dimension: &'static str,
        field: &'static str,
        proposed: u128,
        ceiling: u128,
    },
}

#[cfg(test)]
mod tests;
