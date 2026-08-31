//! Number-theoretic transforms and the two rejection samplers FIPS 204 builds
//! its public matrix and challenge from.
//!
//! Every function here mirrors one in `py/gen_vectors.py` in the ml-dsa-cairo
//! repository, which is the reference the Cairo verifier was written against,
//! and keeps its name so the two can be diffed by eye.
//!
//! Coefficients are `u32` in `[0, Q)`. Products reach `2^46`, so every multiply
//! widens to `u64` before reducing — the one arithmetic rule this file follows
//! throughout.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

use super::{K_ROWS, L_COLS, N_COEFFS, Q, TAU};

/// One polynomial: 256 coefficients mod Q.
pub(super) type Poly = [u32; N_COEFFS];

const Q64: u64 = Q as u64;

// ZETAS[i] = 1753^bitrev8(i) mod Q, plain (non-Montgomery) domain, matching
// `mldsa/src/tables.cairo`. Built once at first use rather than written out:
// a 256-entry literal is a transcription risk for no gain.
fn zetas() -> &'static [u32; N_COEFFS] {
    use std::sync::OnceLock;
    static ZETAS: OnceLock<[u32; N_COEFFS]> = OnceLock::new();
    ZETAS.get_or_init(|| {
        let mut table = [0u32; N_COEFFS];
        for (index, entry) in table.iter_mut().enumerate() {
            *entry = mod_pow(1753, bitrev8(index as u8));
        }
        table
    })
}

fn mod_pow(base: u32, exponent: u32) -> u32 {
    let mut result: u64 = 1;
    let mut b = u64::from(base) % Q64;
    let mut e = exponent;
    while e > 0 {
        if e % 2 == 1 {
            result = result * b % Q64;
        }
        b = b * b % Q64;
        e /= 2;
    }
    result as u32
}

fn bitrev8(value: u8) -> u32 {
    let mut out = 0u32;
    for bit in 0..8 {
        out = out * 2 + u32::from((value >> bit) & 1);
    }
    out
}

fn inv256() -> u32 {
    use std::sync::OnceLock;
    static INV: OnceLock<u32> = OnceLock::new();
    *INV.get_or_init(|| mod_pow(256, Q - 2))
}

/// Forward number-theoretic transform.
pub(super) fn ntt(input: &Poly) -> Poly {
    let table = zetas();
    let mut a = *input;
    let mut k = 0usize;
    let mut length = 128usize;
    while length >= 1 {
        let mut start = 0usize;
        while start < N_COEFFS {
            k += 1;
            let zeta = u64::from(table[k]);
            for j in start..start + length {
                let t = (zeta * u64::from(a[j + length]) % Q64) as u32;
                a[j + length] = (a[j] + Q - t) % Q;
                a[j] = (a[j] + t) % Q;
            }
            start += 2 * length;
        }
        length /= 2;
    }
    a
}

/// Inverse number-theoretic transform, including the 1/256 factor.
pub(super) fn intt(input: &Poly) -> Poly {
    let table = zetas();
    let mut a = *input;
    let mut k = N_COEFFS;
    let mut length = 1usize;
    while length < N_COEFFS {
        let mut start = 0usize;
        while start < N_COEFFS {
            k -= 1;
            let zeta = u64::from(Q - table[k]);
            for j in start..start + length {
                let t = a[j];
                a[j] = (t + a[j + length]) % Q;
                a[j + length] = (zeta * u64::from(t + Q - a[j + length]) % Q64) as u32;
            }
            start += 2 * length;
        }
        length *= 2;
    }
    let factor = u64::from(inv256());
    for coefficient in &mut a {
        *coefficient = (factor * u64::from(*coefficient) % Q64) as u32;
    }
    a
}

// Rejection-samples one polynomial of A from a 34-byte seed. The 840-byte
// SHAKE-128 read is five blocks, which succeeds with overwhelming probability;
// a short read would be a silent divergence from the contract, so it is an
// error rather than a truncated polynomial.
fn rej_ntt_poly(seed: &[u8; 34]) -> Option<Poly> {
    let mut hasher = Shake128::default();
    hasher.update(seed);
    let mut stream = [0u8; 840];
    hasher.finalize_xof().read(&mut stream);

    let mut out = [0u32; N_COEFFS];
    let mut filled = 0usize;
    let mut pos = 0usize;
    while filled < N_COEFFS {
        if pos + 3 > stream.len() {
            return None;
        }
        let value = u32::from(stream[pos])
            + 256 * u32::from(stream[pos + 1])
            + 65536 * u32::from(stream[pos + 2] & 0x7f);
        pos += 3;
        if value < Q {
            out[filled] = value;
            filled += 1;
        }
    }
    Some(out)
}

/// Expands `rho` into the K x L public matrix A, in the NTT domain.
///
/// This is an expansion, not a decoding: 7,680 coefficients derived
/// pseudorandomly from 32 bytes, which is why no amount of reading the public
/// key produces it.
pub(super) fn expand_a(rho: &[u8]) -> Option<Vec<Vec<Poly>>> {
    let mut seed = [0u8; 34];
    seed[..32].copy_from_slice(rho.get(..32)?);
    let mut rows = Vec::with_capacity(K_ROWS);
    for r in 0..K_ROWS {
        let mut row = Vec::with_capacity(L_COLS);
        for s in 0..L_COLS {
            seed[32] = s as u8;
            seed[33] = r as u8;
            row.push(rej_ntt_poly(&seed)?);
        }
        rows.push(row);
    }
    Some(rows)
}

/// Derives the challenge polynomial from `c_tilde`: TAU coefficients of +/-1.
///
/// `None` when the rejection loop runs off the end of the 272-byte stream. That
/// is astronomically unlikely on any input, but `c_tilde` arrives inside an
/// attacker-supplied signature, so it resolves to a rejected signature rather
/// than a panic crossing the WASM or C boundary.
pub(super) fn sample_in_ball(c_tilde: &[u8]) -> Option<Poly> {
    let mut hasher = Shake256::default();
    hasher.update(c_tilde);
    let mut stream = [0u8; 272];
    hasher.finalize_xof().read(&mut stream);

    // The first eight bytes are a little-endian sign bitfield. Folded by hand
    // rather than through `from_le_bytes` so this carries no panic path at all.
    let mut signs = 0u64;
    for byte in stream[..8].iter().rev() {
        signs = (signs << 8) | u64::from(*byte);
    }
    let mut pos = 8usize;
    let mut c = [0u32; N_COEFFS];
    for i in (N_COEFFS - TAU)..N_COEFFS {
        let j = loop {
            let candidate = usize::from(*stream.get(pos)?);
            pos += 1;
            if candidate <= i {
                break candidate;
            }
        };
        c[i] = c[j];
        c[j] = if signs & 1 == 0 { 1 } else { Q - 1 };
        signs >>= 1;
    }
    Some(c)
}
