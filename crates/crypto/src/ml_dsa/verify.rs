//! FIPS 204 Algorithm 8, following `verify()` in `py/gen_vectors.py`.
//!
//! The `w` rows this computes on the way are exactly what the on-chain hints
//! commit to, so the payload builder reuses this result rather than recomputing
//! them and risking a different answer. That is why verification returns a
//! transcript and not a bool.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use super::encode::{unpack_hints, unpack_t1, unpack_z, use_hint};
use super::key::shake256_64;
use super::ntt::{expand_a, intt, ntt, sample_in_ball, Poly};
use super::{
    CT_BYTES, D_BITS, K_ROWS, L_COLS, N_COEFFS, Q, T1_ROW_BYTES, W1_ROW_BYTES, Z_BOUND, Z_BYTES,
};

/// A completed verification: the verdict, and the `w` rows it went through.
pub(super) struct Transcript {
    pub(super) ok: bool,
    pub(super) w_rows: Vec<Poly>,
}

const EMPTY: fn() -> Transcript = || Transcript {
    ok: false,
    w_rows: Vec::new(),
};

/// Verifies a signature and returns its transcript.
///
/// Every rejection path yields `ok: false` rather than an error: the caller is
/// gating a broadcast and wants one decision it can trust, and all three inputs
/// are attacker-reachable.
pub(super) fn verify_internal(public_key: &[u8], message: &[u8], signature: &[u8]) -> Transcript {
    let Some(hints) = signature
        .get(CT_BYTES + Z_BYTES * L_COLS..)
        .and_then(unpack_hints)
    else {
        return EMPTY();
    };

    let mut z_hat = Vec::with_capacity(L_COLS);
    for j in 0..L_COLS {
        let start = CT_BYTES + Z_BYTES * j;
        let Some(unpacked) = signature.get(start..start + Z_BYTES).and_then(unpack_z) else {
            return EMPTY();
        };
        if unpacked.max_abs >= Z_BOUND {
            return EMPTY();
        }
        z_hat.push(ntt(&unpacked.coefficients));
    }

    let tr = shake256_64(public_key);
    let mut mu_hasher = Shake256::default();
    mu_hasher.update(&tr);
    mu_hasher.update(&[0, 0]);
    mu_hasher.update(message);
    let mut mu = [0u8; 64];
    mu_hasher.finalize_xof().read(&mut mu);

    let Some(c_tilde) = signature.get(..CT_BYTES) else {
        return EMPTY();
    };
    let Some(c_hat) = sample_in_ball(c_tilde).map(|c| ntt(&c)) else {
        return EMPTY();
    };
    let Some(a_hat) = public_key.get(..32).and_then(expand_a) else {
        return EMPTY();
    };

    let mut w_rows = Vec::with_capacity(K_ROWS);
    let mut w1_bytes = vec![0u8; K_ROWS * W1_ROW_BYTES];
    for i in 0..K_ROWS {
        let start = 32 + T1_ROW_BYTES * i;
        let Some(mut t1) = public_key
            .get(start..start + T1_ROW_BYTES)
            .and_then(unpack_t1)
        else {
            return EMPTY();
        };
        for coefficient in &mut t1 {
            *coefficient <<= D_BITS;
        }
        let t1_hat = ntt(&t1);
        let Some(row) = a_hat.get(i) else {
            return EMPTY();
        };

        let mut w = [0u32; N_COEFFS];
        for t in 0..N_COEFFS {
            let mut accumulator = 0u64;
            for (j, z) in z_hat.iter().enumerate() {
                let Some(a) = row.get(j) else {
                    return EMPTY();
                };
                accumulator += u64::from(a[t]) * u64::from(z[t]);
            }
            // `+ Q*Q` keeps the subtraction non-negative without a signed type:
            // the product below it is at most (Q-1)^2.
            let challenge = u64::from(c_hat[t]) * u64::from(t1_hat[t]);
            w[t] = ((accumulator + u64::from(Q) * u64::from(Q) - challenge) % u64::from(Q)) as u32;
        }
        let w_row = intt(&w);

        let positions = &hints[i];
        for g in 0..W1_ROW_BYTES {
            let low = use_hint(positions.contains(&((2 * g) as u8)), w_row[2 * g]);
            let high = use_hint(positions.contains(&((2 * g + 1) as u8)), w_row[2 * g + 1]);
            w1_bytes[i * W1_ROW_BYTES + g] = (low + 16 * high) as u8;
        }
        w_rows.push(w_row);
    }

    let mut expected_hasher = Shake256::default();
    expected_hasher.update(&mu);
    expected_hasher.update(&w1_bytes);
    let mut expected = [0u8; CT_BYTES];
    expected_hasher.finalize_xof().read(&mut expected);

    // Length-checked, not constant-time: both operands are public, and the
    // result gates a broadcast rather than a secret.
    Transcript {
        ok: expected.as_slice() == c_tilde,
        w_rows,
    }
}
