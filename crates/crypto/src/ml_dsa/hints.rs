//! The Schwartz-Zippel hints.
//!
//! The contract checks an integer identity the felt-domain evaluation alone
//! cannot: for each row, `A.z - c.T` recomposes exactly as
//! `w + Q*M' + (X^256 + 1)*K'`. Those two correction rows are what the signer
//! supplies and the contract verifies, and they only exist as unreduced
//! integers — hence `i128` throughout this file rather than the `u32` mod-Q
//! arithmetic everywhere else.
//!
//! The magnitudes involved: `A` coefficients are under 2^23 and signed `z`
//! under 2^19, so one convolution term is under 2^42 and a 256-term row summed
//! over five columns stays under 2^53. The challenge product is under 2^54.
//! `i128` therefore has more than 70 bits of headroom; it is chosen to mirror
//! the TypeScript `bigint` original exactly, not because `i64` would overflow.

use krusty_kms_common::{KmsError, Result};

use super::encode::unpack_z_signed;
use super::key::KeyMaterial;
use super::ntt::{sample_in_ball, Poly};
use super::{CT_BYTES, K_ROWS, L_COLS, N_COEFFS, OFFSET_K, OFFSET_M, Q, Z_BYTES};

const CONVOLUTION_LEN: usize = 2 * N_COEFFS - 1;

/// The two witness rows, offset so every value is non-negative before packing.
pub(super) struct HintRows {
    pub(super) m: Vec<u128>,
    pub(super) k: Vec<u128>,
}

/// Exact integer convolution of two polynomials, unreduced.
fn convolve(a: &[i128], b: &[i128]) -> Vec<i128> {
    let mut out = vec![0i128; CONVOLUTION_LEN];
    for (i, ai) in a.iter().enumerate() {
        if *ai == 0 {
            continue;
        }
        for (j, bj) in b.iter().enumerate() {
            out[i + j] += ai * bj;
        }
    }
    out
}

fn widen(poly: &Poly) -> Vec<i128> {
    poly.iter().map(|c| i128::from(*c)).collect()
}

/// Derives `M'` and `K'` for every row from the signature and the `w` rows
/// verification already produced.
pub(super) fn hint_rows(
    material: &KeyMaterial,
    signature: &[u8],
    w_rows: &[Poly],
) -> Result<HintRows> {
    let invalid = || KmsError::CryptoError("ML-DSA signature is malformed".into());

    let mut z_rows = Vec::with_capacity(L_COLS);
    for j in 0..L_COLS {
        let start = CT_BYTES + Z_BYTES * j;
        let signed = signature
            .get(start..start + Z_BYTES)
            .and_then(unpack_z_signed)
            .ok_or_else(invalid)?;
        z_rows.push(signed.iter().map(|c| i128::from(*c)).collect::<Vec<_>>());
    }
    let c_poly = signature
        .get(..CT_BYTES)
        .and_then(sample_in_ball)
        .map(|c| widen(&c))
        .ok_or_else(invalid)?;

    let big_q = i128::from(Q);
    let mut m = Vec::with_capacity(K_ROWS * N_COEFFS);
    let mut k = Vec::with_capacity(K_ROWS * N_COEFFS);

    for i in 0..K_ROWS {
        let a_row = material.a_coefficients.get(i).ok_or_else(invalid)?;
        let mut u = vec![0i128; CONVOLUTION_LEN];
        for (j, z) in z_rows.iter().enumerate() {
            let product = convolve(&widen(a_row.get(j).ok_or_else(invalid)?), z);
            for (slot, value) in product.iter().enumerate() {
                u[slot] += value;
            }
        }
        let challenge = convolve(&c_poly, &widen(material.t_rows.get(i).ok_or_else(invalid)?));
        for (slot, value) in challenge.iter().enumerate() {
            u[slot] -= value;
        }

        // K' is the wrapped high half: X^256 = -1 in the ring, so the degree
        // 256..511 tail folds back down. The last slot has nothing above it.
        let k_row: Vec<i128> = (0..N_COEFFS)
            .map(|t| if t < N_COEFFS - 1 { u[t + N_COEFFS] } else { 0 })
            .collect();
        let w_row = w_rows.get(i).ok_or_else(invalid)?;
        let mut m_row = Vec::with_capacity(N_COEFFS);
        for t in 0..N_COEFFS {
            let low = u[t] - k_row[t] - i128::from(w_row[t]);
            if low % big_q != 0 {
                return Err(KmsError::CryptoError(
                    "ML-DSA hint recomposition is not divisible by Q".into(),
                ));
            }
            m_row.push(low / big_q);
        }

        assert_recomposition(&u, w_row, &m_row, &k_row, big_q)?;
        m.extend(m_row.iter().map(|v| (v + OFFSET_M) as u128));
        k.extend(k_row.iter().map(|v| (v + OFFSET_K) as u128));
    }

    Ok(HintRows { m, k })
}

// The contract rejects a wrong payload with no useful error, so the identity it
// checks is checked here first, exactly, before anything is emitted.
fn assert_recomposition(
    u: &[i128],
    w_row: &Poly,
    m_row: &[i128],
    k_row: &[i128],
    big_q: i128,
) -> Result<()> {
    let mut recomposed = vec![0i128; CONVOLUTION_LEN];
    for t in 0..N_COEFFS {
        recomposed[t] = i128::from(w_row[t]) + big_q * m_row[t] + k_row[t];
    }
    for t in 0..N_COEFFS - 1 {
        recomposed[t + N_COEFFS] += k_row[t];
    }
    if recomposed != u {
        return Err(KmsError::CryptoError(
            "ML-DSA hint recomposition does not reproduce the integer identity".into(),
        ));
    }
    assert_hint_range(m_row, OFFSET_M, "M")?;
    assert_hint_range(k_row, OFFSET_K, "K")
}

// The hint rows are packed into fixed-width fields, so a value past its offset
// would wrap into its neighbour and be rejected on chain with no diagnosis.
fn assert_hint_range(row: &[i128], offset: i128, name: &str) -> Result<()> {
    for value in row {
        if *value >= offset || -*value >= offset {
            return Err(KmsError::CryptoError(format!(
                "ML-DSA {name} hint out of range"
            )));
        }
    }
    Ok(())
}
