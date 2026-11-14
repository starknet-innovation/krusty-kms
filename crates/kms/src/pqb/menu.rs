// Portions ported from fireblocks-labs/pqb, Copyright (c) 2026 Fireblocks Ltd.
// MIT license: ../../licenses/PQB-MIT.txt (included in this crate package).
//! Secret signature menus and public grinder points for the fixed PQB profile.
use super::{invalid, PqbPublicMenu, PqbVault, Result};
use crypto_bigint::U256;
use k256::elliptic_curve::{ff::PrimeField, sec1::ToSec1Point};
use k256::{AffinePoint, ProjectivePoint, PublicKey, Scalar};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(super) struct Menu {
    pub(super) r: [u8; 32],
    pub(super) signatures: Zeroizing<Vec<Vec<u8>>>,
    scalars: Zeroizing<Vec<Scalar>>,
}

impl PqbVault {
    pub(super) fn menus(&self) -> Result<[Menu; 3]> {
        Ok([
            self.menu("pin", 12, false)?,
            self.menu("round0", 16, true)?,
            self.menu("round1", 16, true)?,
        ])
    }
    fn menu(&self, tag: &str, count: usize, small: bool) -> Result<Menu> {
        let r = self.menu_r(tag, small)?;
        let seed = self.secret(&format!("r5close-indep-menu-{tag}"));
        let mut signatures = Zeroizing::new(Vec::with_capacity(count));
        let mut scalars = Zeroizing::new(Vec::with_capacity(count));
        for j in 0..count {
            let mut h = Sha256::new();
            h.update(seed.as_ref());
            h.update(format!("|{j}").as_bytes());
            let digest = Zeroizing::new(<[u8; 32]>::from(h.finalize()));
            let x = Zeroizing::new(U256::from_be_slice(digest.as_ref()));
            let s = Zeroizing::new((*x >> 6u32) | (U256::ONE << 250u32));
            let bytes = Zeroizing::new(<[u8; 32]>::from(s.to_be_bytes()));
            scalars.push(scalar(&bytes)?);
            signatures.push(der_signature(&r, &bytes));
        }
        Ok(Menu {
            r,
            signatures,
            scalars,
        })
    }
    fn menu_r(&self, tag: &str, small: bool) -> Result<[u8; 32]> {
        if small {
            for r in 128..200u64 {
                let x = U256::from(r);
                if lift(&x.to_be_bytes().into(), false).is_some()
                    && lift(&x.wrapping_add(&ORDER).to_be_bytes().into(), false).is_some()
                {
                    return Ok(x.to_be_bytes().into());
                }
            }
        } else {
            let seed = self.secret(&format!("r2f-menu-{tag}"));
            let mut h = Sha256::new();
            h.update(b"r-");
            h.update(seed.as_ref());
            // r is public and safe to retain outside zeroizing buffers.
            let mut bytes: [u8; 32] = h.finalize().into();
            bytes[0] &= 0x7f;
            let base = U256::from_be_slice(&bytes);
            for offset in 0..(1 << 18) {
                let candidate = base.wrapping_add(&U256::from(offset as u64)) & (U256::MAX >> 1u32);
                if candidate != U256::ZERO && lift(&candidate.to_be_bytes().into(), false).is_some()
                {
                    return Ok(candidate.to_be_bytes().into());
                }
            }
        }
        Err(invalid("could not derive menu r"))
    }
}

const ORDER: U256 =
    U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const FIELD: U256 =
    U256::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

impl Menu {
    pub(super) fn public(&self) -> Result<PqbPublicMenu> {
        super::require_wiped_hash::<Sha1>();
        let commitments = self
            .signatures
            .iter()
            .map(|sig| Sha1::digest(sig).into())
            .collect();
        let inverse = scalar(&self.r)?
            .invert()
            .into_option()
            .ok_or_else(|| invalid("zero menu r"))?;
        let mut recovery_points = Vec::new();
        let r = U256::from_be_slice(&self.r);
        for add_n in [false, true] {
            let (x, carry) = r.carrying_add(
                &if add_n { ORDER } else { U256::ZERO },
                crypto_bigint::Limb::ZERO,
            );
            if carry != crypto_bigint::Limb::ZERO || x >= FIELD {
                continue;
            }
            for odd in [false, true] {
                if let Some(point) = lift(&x.to_be_bytes().into(), odd) {
                    let points = self
                        .scalars
                        .iter()
                        .map(|s| {
                            let factor = Zeroizing::new(*s * inverse);
                            let p = (ProjectivePoint::from(point) * *factor)
                                .to_affine()
                                .to_sec1_point(false);
                            let mut bytes = [0; 65];
                            bytes.copy_from_slice(p.as_bytes());
                            bytes
                        })
                        .collect();
                    recovery_points.push(points);
                }
            }
        }
        Ok(PqbPublicMenu {
            r: self.r,
            commitments,
            recovery_points,
        })
    }
}

fn scalar(bytes: &[u8; 32]) -> Result<Scalar> {
    Scalar::from_repr((*bytes).into())
        .into_option()
        .ok_or_else(|| invalid("invalid menu scalar"))
}
fn lift(x: &[u8; 32], odd: bool) -> Option<AffinePoint> {
    let mut encoded = [0; 33];
    encoded[0] = if odd { 3 } else { 2 };
    encoded[1..].copy_from_slice(x);
    PublicKey::from_sec1_bytes(&encoded)
        .ok()
        .map(|key| *key.as_affine())
}

/// Canonical DER plus the frozen SIGHASH_ALL byte; intermediate secret bytes wipe.
pub(super) fn der_signature(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut body = Zeroizing::new(Vec::with_capacity(70));
    for value in [r, s] {
        let start = value.iter().position(|b| *b != 0).unwrap_or(31);
        let bytes = &value[start..];
        let pad = usize::from(bytes[0] & 0x80 != 0);
        body.extend([2, (bytes.len() + pad) as u8]);
        if pad != 0 {
            body.push(0);
        }
        body.extend(bytes);
    }
    let mut out = Vec::with_capacity(body.len() + 3);
    out.extend([0x30, body.len() as u8]);
    out.extend(body.iter());
    out.push(1);
    out
}

pub(super) fn dummy_signatures() -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(109);
    for r in (1..128u64)
        .filter(|r| lift(&U256::from(*r).to_be_bytes().into(), false).is_some())
        .step_by(4)
    {
        for s in 1..128u64 {
            out.push(der_signature(
                &U256::from(r).to_be_bytes().into(),
                &U256::from(s).to_be_bytes().into(),
            ));
            if out.len() == 109 {
                return out;
            }
        }
    }
    out
}
