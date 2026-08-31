//! FIPS 204 bit-unpacking, and the hint decoder.
//!
//! Everything in this file reads attacker-supplied bytes: a public key or a
//! signature off the wire. So every malformed shape returns `None` and becomes
//! a rejected signature. Nothing here panics, indexes unchecked, or truncates.
//!
//! Named after `py/gen_vectors.py` in the ml-dsa-cairo repository, like the rest
//! of this module.

use super::ntt::Poly;
use super::{GAMMA1, GAMMA1_FIELD, GAMMA2, K_ROWS, N_COEFFS, OMEGA, Q};

// Reads a little-endian group of five bytes. The value runs to 40 bits, so the
// accumulator is u64 — the TypeScript original spells this arithmetically for
// the same reason, because 32-bit bitwise ops would truncate it silently.
fn read_five(bytes: &[u8], offset: usize) -> Option<u64> {
    let mut value = 0u64;
    for index in (0..5).rev() {
        value = value * 256 + u64::from(*bytes.get(offset + index)?);
    }
    Some(value)
}

/// Unpacks one row of t1: 320 bytes of ten-bit fields into 256 coefficients.
pub(super) fn unpack_t1(bytes: &[u8]) -> Option<Poly> {
    let mut out = [0u32; N_COEFFS];
    for group in 0..64 {
        let mut value = read_five(bytes, 5 * group)?;
        for field in 0..4 {
            out[4 * group + field] = (value % 1024) as u32;
            value /= 1024;
        }
    }
    Some(out)
}

/// One z polynomial reduced mod Q, with the largest absolute centred value the
/// caller checks against the rejection bound.
pub(super) struct UnpackedZ {
    pub(super) coefficients: Poly,
    pub(super) max_abs: u32,
}

/// Unpacks one z polynomial from its 640 bytes of twenty-bit fields.
pub(super) fn unpack_z(bytes: &[u8]) -> Option<UnpackedZ> {
    let mut coefficients = [0u32; N_COEFFS];
    let mut max_abs = 0u32;
    for group in 0..128 {
        let value = read_five(bytes, 5 * group)?;
        let low = value % u64::from(GAMMA1_FIELD);
        let high = value / u64::from(GAMMA1_FIELD);
        for (slot, raw) in [low, high].into_iter().enumerate() {
            // Centring can go negative, so it happens in i64 and only the
            // magnitude and the reduced value come back out.
            let centred = i64::from(GAMMA1) - raw as i64;
            max_abs = max_abs.max(centred.unsigned_abs() as u32);
            coefficients[2 * group + slot] = centred.rem_euclid(i64::from(Q)) as u32;
        }
    }
    Some(UnpackedZ {
        coefficients,
        max_abs,
    })
}

/// Unpacks one z polynomial as the signed integers the hint recomposition
/// needs.
///
/// The Cairo verifier evaluates the raw wire fields and corrects by GAMMA1 * G,
/// so the hints must use this representation rather than the mod-Q one.
pub(super) fn unpack_z_signed(bytes: &[u8]) -> Option<[i32; N_COEFFS]> {
    let mut out = [0i32; N_COEFFS];
    for group in 0..128 {
        let value = read_five(bytes, 5 * group)?;
        let low = (value % u64::from(GAMMA1_FIELD)) as i64;
        let high = (value / u64::from(GAMMA1_FIELD)) as i64;
        out[2 * group] = (i64::from(GAMMA1) - low) as i32;
        out[2 * group + 1] = (i64::from(GAMMA1) - high) as i32;
    }
    Some(out)
}

/// Unpacks the hint bitfield into one sorted position list per row, or `None`
/// when it is malformed.
pub(super) fn unpack_hints(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut rows = Vec::with_capacity(K_ROWS);
    let mut index = 0usize;
    for row in 0..K_ROWS {
        let end = usize::from(*bytes.get(OMEGA + row)?);
        if end < index || end > OMEGA {
            return None;
        }
        rows.push(strictly_increasing(bytes, index, end)?);
        index = end;
    }
    // Trailing slots must be zero, or one hint set would have several spellings.
    if bytes.get(index..OMEGA)?.iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(rows)
}

// Positions within a row must be strictly increasing, which is what makes the
// encoding canonical: two spellings of one hint set would be two signatures the
// contract treats alike. RustCrypto's `ml-dsa` shipped GHSA-5x2r-hc65-25f9 for
// omitting exactly this check, so it is deliberately its own function.
fn strictly_increasing(bytes: &[u8], from: usize, to: usize) -> Option<Vec<u8>> {
    let mut positions = Vec::with_capacity(to.saturating_sub(from));
    for index in from..to {
        let current = *bytes.get(index)?;
        if index > from && current <= *bytes.get(index - 1)? {
            return None;
        }
        positions.push(current);
    }
    Some(positions)
}

/// Recovers the high bits of one coefficient given its hint bit.
pub(super) fn use_hint(hint: bool, r: u32) -> u32 {
    let quotient = r / (2 * GAMMA2);
    let remainder = r % (2 * GAMMA2);
    let (high, positive) = if remainder <= GAMMA2 {
        (
            if quotient == 16 { 0 } else { quotient },
            remainder != 0 && quotient != 16,
        )
    } else {
        (if quotient == 15 { 0 } else { quotient + 1 }, false)
    };
    if !hint {
        return high;
    }
    if positive {
        (high + 1) % 16
    } else {
        (high + 15) % 16
    }
}
