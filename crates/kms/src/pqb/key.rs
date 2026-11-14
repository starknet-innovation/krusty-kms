// Portions ported from fireblocks-labs/pqb, Copyright (c) 2026 Fireblocks Ltd.
// MIT license: ../../licenses/PQB-MIT.txt (included in this crate package).
//! Secret derivation; no arbitrary-label operation crosses the public boundary.
use super::{PqbVault, Result};
use crypto_bigint::{NonZero, U256};
use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

const ORDER_MINUS_ONE: NonZero<U256> = NonZero::<U256>::new_unwrap(U256::from_be_hex(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
));

impl PqbVault {
    pub(super) fn secret(&self, label: &str) -> Zeroizing<[u8; 32]> {
        let mut h = Sha256::new();
        h.update(b"pqb/v1|");
        h.update(self.seed.as_ref());
        h.update(b"|");
        h.update(label.as_bytes());
        take_secret_digest(&mut h.finalize())
    }
    pub(super) fn hors(&self, index: usize) -> Zeroizing<[u8; 20]> {
        let secret = self.secret(&format!("r2g4-hors-{index}"));
        let mut out = Zeroizing::new([0; 20]);
        out.copy_from_slice(&secret[..20]);
        out
    }
    pub(super) fn cosig_key(&self) -> Result<SigningKey> {
        signing_key(&self.secret("cosig-key"))
    }
    pub(super) fn deposit_key(&self) -> Result<SigningKey> {
        let digest = crate::zeroizing_hmac::hmac::<Sha512, 64>(
            self.seed.as_ref(),
            &[b"pqb/deposit-key/v1"],
        )?;
        let mut bytes = Zeroizing::new([0; 32]);
        bytes.copy_from_slice(&digest[..32]);
        signing_key(&bytes)
    }
}

/// Transfer a secret digest into wiped storage and clear the hash output too.
/// The hash's zeroize feature covers its state, not its returned output buffer.
pub(super) fn take_secret_digest(output: &mut sha2::digest::Output<Sha256>) -> Zeroizing<[u8; 32]> {
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(output);
    output.as_mut_slice().zeroize();
    secret
}

/// PQB maps 256 bits to [1,n-1] using mod(n-1)+1, not mod n.
fn signing_key(bytes: &[u8; 32]) -> Result<SigningKey> {
    let value = Zeroizing::new(U256::from_be_slice(bytes));
    let reduced = Zeroizing::new(value.rem(&ORDER_MINUS_ONE).wrapping_add(&U256::ONE));
    let encoded = Zeroizing::new(reduced.to_be_bytes());
    SigningKey::from_slice(encoded.as_ref()).map_err(|e| super::invalid(e.to_string()))
}

pub(super) fn public_key(key: &SigningKey) -> [u8; 33] {
    let mut bytes = [0; 33];
    bytes.copy_from_slice(key.verifying_key().to_sec1_point(true).as_bytes());
    bytes
}
