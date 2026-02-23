//! Precision-safe token amount representation.

use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use std::fmt;

use crate::{KmsError, Result};

/// A token amount with associated decimal precision.
///
/// Stores the raw (smallest-unit) value plus the number of decimals,
/// avoiding floating-point imprecision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Amount {
    raw: u128,
    decimals: u8,
}

impl Amount {
    /// Create from the raw (smallest-unit) integer value.
    pub fn from_raw(raw: u128, decimals: u8) -> Self {
        Self { raw, decimals }
    }

    /// Parse a human-readable decimal string (e.g. `"1.5"`) into an `Amount`.
    pub fn from_human(s: &str, decimals: u8) -> Result<Self> {
        let s = s.trim();
        let factor = 10u128
            .checked_pow(decimals as u32)
            .ok_or_else(|| KmsError::InvalidAmount("decimals too large".into()))?;

        let raw = if let Some(dot) = s.find('.') {
            let integer_part = &s[..dot];
            let frac_part = &s[dot + 1..];

            if frac_part.len() > decimals as usize {
                return Err(KmsError::InvalidAmount(format!(
                    "too many decimal places (max {})",
                    decimals
                )));
            }

            let int_val: u128 = if integer_part.is_empty() {
                0
            } else {
                integer_part
                    .parse()
                    .map_err(|_| KmsError::InvalidAmount(format!("invalid number: {}", s)))?
            };

            let padded_frac = format!("{:0<width$}", frac_part, width = decimals as usize);
            let frac_val: u128 = padded_frac
                .parse()
                .map_err(|_| KmsError::InvalidAmount(format!("invalid fraction: {}", s)))?;

            int_val
                .checked_mul(factor)
                .and_then(|v| v.checked_add(frac_val))
                .ok_or_else(|| KmsError::InvalidAmount("overflow".into()))?
        } else {
            let int_val: u128 = s
                .parse()
                .map_err(|_| KmsError::InvalidAmount(format!("invalid number: {}", s)))?;
            int_val
                .checked_mul(factor)
                .ok_or_else(|| KmsError::InvalidAmount("overflow".into()))?
        };

        Ok(Self { raw, decimals })
    }

    /// The raw (smallest-unit) value.
    pub fn raw(&self) -> u128 {
        self.raw
    }

    /// Number of decimals.
    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Convert to a human-readable decimal string.
    pub fn to_human(&self) -> String {
        if self.decimals == 0 {
            return self.raw.to_string();
        }
        let factor = 10u128.pow(self.decimals as u32);
        let integer = self.raw / factor;
        let fraction = self.raw % factor;
        if fraction == 0 {
            format!("{}.0", integer)
        } else {
            let frac_str = format!("{:0>width$}", fraction, width = self.decimals as usize);
            let trimmed = frac_str.trim_end_matches('0');
            format!("{}.{}", integer, trimmed)
        }
    }

    /// Encode as a Starknet u256 `(low, high)` Felt pair.
    ///
    /// Since the raw value is `u128`, it fits entirely in the low limb.
    pub fn to_u256(&self) -> (Felt, Felt) {
        (Felt::from(self.raw), Felt::ZERO)
    }

    /// Checked addition (decimals must match).
    pub fn checked_add(&self, other: &Amount) -> Result<Amount> {
        if self.decimals != other.decimals {
            return Err(KmsError::InvalidAmount(
                "cannot add amounts with different decimals".into(),
            ));
        }
        let raw = self
            .raw
            .checked_add(other.raw)
            .ok_or_else(|| KmsError::InvalidAmount("overflow".into()))?;
        Ok(Amount {
            raw,
            decimals: self.decimals,
        })
    }

    /// Checked subtraction (decimals must match).
    pub fn checked_sub(&self, other: &Amount) -> Result<Amount> {
        if self.decimals != other.decimals {
            return Err(KmsError::InvalidAmount(
                "cannot subtract amounts with different decimals".into(),
            ));
        }
        let raw = self
            .raw
            .checked_sub(other.raw)
            .ok_or_else(|| KmsError::InvalidAmount("underflow".into()))?;
        Ok(Amount {
            raw,
            decimals: self.decimals,
        })
    }

    /// Returns true if the amount is zero.
    pub fn is_zero(&self) -> bool {
        self.raw == 0
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_human())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_raw() {
        let amt = Amount::from_raw(1_500_000_000_000_000_000, 18);
        assert_eq!(amt.to_human(), "1.5");
    }

    #[test]
    fn test_from_human_integer() {
        let amt = Amount::from_human("100", 18).unwrap();
        assert_eq!(amt.raw(), 100_000_000_000_000_000_000);
    }

    #[test]
    fn test_from_human_decimal() {
        let amt = Amount::from_human("1.5", 18).unwrap();
        assert_eq!(amt.raw(), 1_500_000_000_000_000_000);
    }

    #[test]
    fn test_from_human_leading_dot() {
        let amt = Amount::from_human(".5", 18).unwrap();
        assert_eq!(amt.raw(), 500_000_000_000_000_000);
    }

    #[test]
    fn test_from_human_too_many_decimals() {
        assert!(Amount::from_human("1.1234567", 6).is_err());
    }

    #[test]
    fn test_to_human_whole() {
        let amt = Amount::from_raw(2_000_000, 6);
        assert_eq!(amt.to_human(), "2.0");
    }

    #[test]
    fn test_to_u256() {
        let amt = Amount::from_raw(1000, 6);
        let (low, high) = amt.to_u256();
        assert_eq!(low, Felt::from(1000u64));
        assert_eq!(high, Felt::ZERO);
    }

    #[test]
    fn test_checked_add() {
        let a = Amount::from_raw(100, 6);
        let b = Amount::from_raw(200, 6);
        let c = a.checked_add(&b).unwrap();
        assert_eq!(c.raw(), 300);
    }

    #[test]
    fn test_checked_add_different_decimals() {
        let a = Amount::from_raw(100, 6);
        let b = Amount::from_raw(200, 18);
        assert!(a.checked_add(&b).is_err());
    }

    #[test]
    fn test_checked_sub() {
        let a = Amount::from_raw(300, 6);
        let b = Amount::from_raw(100, 6);
        let c = a.checked_sub(&b).unwrap();
        assert_eq!(c.raw(), 200);
    }

    #[test]
    fn test_checked_sub_underflow() {
        let a = Amount::from_raw(100, 6);
        let b = Amount::from_raw(200, 6);
        assert!(a.checked_sub(&b).is_err());
    }

    #[test]
    fn test_is_zero() {
        assert!(Amount::from_raw(0, 18).is_zero());
        assert!(!Amount::from_raw(1, 18).is_zero());
    }

    #[test]
    fn test_display() {
        let amt = Amount::from_raw(1_500_000, 6);
        assert_eq!(format!("{}", amt), "1.5");
    }

    #[test]
    fn test_zero_decimals() {
        let amt = Amount::from_raw(42, 0);
        assert_eq!(amt.to_human(), "42");
    }
}
