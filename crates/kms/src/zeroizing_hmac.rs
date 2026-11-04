//! HMAC (RFC 2104) and HKDF-Expand (RFC 5869) whose key schedule and hash
//! states are wiped when they drop.
//!
//! Every HMAC in this crate whose key or message is secret goes through here
//! rather than the `hmac` crate. `hmac` 0.13, even with its `zeroize`
//! feature, leaves the padded key in an unwiped local of `new_from_slice` and
//! the inner hash in another of its finalization.
//!
//! Wiped: the padded key (a `Zeroizing` buffer), both SHA-2 states and their
//! block buffers (`D: ZeroizeOnDrop`, which `sha2` implements only with its
//! `zeroize` feature, so dropping the feature fails the build), the inner
//! hash, and the output (`Zeroizing`). Not wiped: copies the compiler makes
//! when it moves a value, register spills, and the temporaries of the SHA-2
//! compression and finalization functions.
//!
//! Keys longer than one block are refused rather than hashed: no caller needs
//! one, and refusing keeps the padded key the whole key schedule.

use krusty_kms_common::{KmsError, Result};
use sha2::digest::common::BlockSizeUser;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// SHA-512's block, the largest of the hashes used here.
const MAX_HMAC_BLOCK: usize = 128;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;
const SHA256_LEN: usize = 32;

/// `HMAC-D(key, message[0] || message[1] || ...)`.
///
/// # Errors
///
/// `CryptoError` if `key` is longer than one block of `D`, or `N` is not
/// `D`'s output size. Both are fixed by the caller, never by input data.
pub(crate) fn hmac<D, const N: usize>(key: &[u8], message: &[&[u8]]) -> Result<Zeroizing<[u8; N]>>
where
    D: Digest + BlockSizeUser + ZeroizeOnDrop,
{
    let block = D::block_size();
    if key.len() > block || block > MAX_HMAC_BLOCK || N != <D as Digest>::output_size() {
        return Err(KmsError::CryptoError(
            "HMAC key must fit one block and the output its digest".to_string(),
        ));
    }
    let mut pad = Zeroizing::new([0u8; MAX_HMAC_BLOCK]);
    let pad = &mut pad[..block];
    pad[..key.len()].copy_from_slice(key);
    pad.iter_mut().for_each(|byte| *byte ^= IPAD);
    let mut inner = D::new_with_prefix(&*pad);
    for part in message {
        inner.update(part);
    }
    let mut inner_hash = inner.finalize();
    pad.iter_mut().for_each(|byte| *byte ^= IPAD ^ OPAD);
    let outer = D::new_with_prefix(&*pad).chain_update(&inner_hash);
    inner_hash.as_mut_slice().zeroize();
    Ok(take_output(&mut outer.finalize()))
}

/// HKDF-Expand with HMAC-SHA256: the first `L` bytes of
/// `T(1) || T(2) || ...`, where `T(i) = HMAC(prk, T(i-1) || info || i)`.
///
/// # Errors
///
/// `CryptoError` if `L` exceeds the `255 * 32` bytes HKDF can produce.
pub(crate) fn hkdf_sha256_expand<const L: usize>(
    prk: &[u8; SHA256_LEN],
    info: &[u8],
) -> Result<Zeroizing<[u8; L]>> {
    if L > 255 * SHA256_LEN {
        return Err(KmsError::CryptoError(
            "HKDF-SHA256 output is limited to 8160 bytes".to_string(),
        ));
    }
    let mut okm = Zeroizing::new([0u8; L]);
    let mut previous = Zeroizing::new([0u8; SHA256_LEN]);
    for (counter, chunk) in (1..=u8::MAX).zip(okm.chunks_mut(SHA256_LEN)) {
        let chained: &[u8] = if counter == 1 { &[] } else { &previous[..] };
        let block = hmac::<Sha256, SHA256_LEN>(prk, &[chained, info, &[counter]])?;
        chunk.copy_from_slice(&block[..chunk.len()]);
        previous.copy_from_slice(&block[..]);
    }
    Ok(okm)
}

/// Copy a secret-bearing buffer into a wiped-on-drop array, then wipe it.
fn take_output<const N: usize>(output: &mut [u8]) -> Zeroizing<[u8; N]> {
    let mut taken = Zeroizing::new([0u8; N]);
    taken.copy_from_slice(&output[..N]);
    output.zeroize();
    taken
}

#[cfg(test)]
mod tests;
