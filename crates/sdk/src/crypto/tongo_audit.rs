//! Audit-hint encoding compatible with `@fatsolutions/tongo-sdk` 1.3.2.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use krusty_kms_common::{KmsError, Result};
use krusty_kms_crypto::{random_bytes, StarkCurve};
use sha2::{Digest, Sha256};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;
use zeroize::Zeroizing;

const PLAINTEXT_SIZE: usize = 48;
const NOISE_SIZE: usize = 44;
const CIPHERTEXT_SIZE: usize = 64;

fn checked_account_nonce(nonce: &Felt) -> Result<u64> {
    let bytes = nonce.to_bytes_be();
    if bytes[..24].iter().any(|byte| *byte != 0) {
        return Err(KmsError::InvalidAmount(
            "Tongo audit nonce exceeds u64".to_string(),
        ));
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&bytes[24..]);
    Ok(u64::from_be_bytes(low))
}

fn derive_tongo_audit_key(
    private_key: &Felt,
    other_public_key: &ProjectivePoint,
    account_nonce: u64,
    tongo_address: &Felt,
) -> Result<Zeroizing<[u8; 32]>> {
    let shared_point = StarkCurve::mul(private_key, Some(other_public_key));
    let affine = shared_point
        .to_affine()
        .map_err(|_| KmsError::PointAtInfinity)?;

    // Tongo's ECDH source is the uncompressed point: 0x04 || x || y.
    let mut shared = Zeroizing::new([0u8; 65]);
    shared[0] = 4;
    shared[1..33].copy_from_slice(&affine.x().to_bytes_be());
    shared[33..].copy_from_slice(&affine.y().to_bytes_be());

    // Salt = SHA256(account nonce, x, y). Info = "tongo", contract, 27 zeros.
    let mut salt_input = Zeroizing::new([0u8; 72]);
    salt_input[..8].copy_from_slice(&account_nonce.to_be_bytes());
    salt_input[8..].copy_from_slice(&shared[1..]);
    let salt: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(&salt_input[..]).into());
    let mut info = [0u8; 64];
    info[..5].copy_from_slice(b"tongo");
    info[5..37].copy_from_slice(&tongo_address.to_bytes_be());

    let hkdf = Hkdf::<Sha256>::new(Some(&salt[..]), &shared[..]);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, &mut key[..])
        .map_err(|_| KmsError::CryptoError("Tongo audit HKDF expansion failed".to_string()))?;
    Ok(key)
}

/// Encrypt a Tongo audit hint for the configured auditor.
///
/// The account nonce and Tongo address must be the same values used in the
/// operation's proof and calldata. The pinned Tongo auditor supports balances
/// only up to `u32::MAX` in this 64-byte hint format.
pub fn encrypt_for_auditor_with_context(
    balance: u128,
    user_private_key: &Felt,
    auditor_public_key: &ProjectivePoint,
    account_nonce: &Felt,
    tongo_address: &Felt,
) -> Result<([u8; CIPHERTEXT_SIZE], [u8; 24])> {
    let balance = u32::try_from(balance).map_err(|_| {
        KmsError::InvalidAmount("Tongo audit hint balance exceeds 32 bits".to_string())
    })?;
    let nonce = checked_account_nonce(account_nonce)?;
    let key = derive_tongo_audit_key(user_private_key, auditor_public_key, nonce, tongo_address)?;

    // Tongo authenticates the entire 48-byte plaintext: 44 random bytes and
    // the four-byte big-endian balance. No unauthenticated padding is appended.
    let mut plaintext = Zeroizing::new([0u8; PLAINTEXT_SIZE]);
    plaintext[..NOISE_SIZE].copy_from_slice(&random_bytes::<NOISE_SIZE>());
    plaintext[NOISE_SIZE..].copy_from_slice(&balance.to_be_bytes());
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| KmsError::CryptoError("invalid Tongo audit key".to_string()))?;
    let nonce_bytes = random_bytes::<24>();
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce_bytes), plaintext.as_ref())
        .map_err(|_| KmsError::CryptoError("Tongo audit encryption failed".to_string()))?;
    let ciphertext: [u8; CIPHERTEXT_SIZE] = ciphertext.try_into().map_err(|_| {
        KmsError::CryptoError("unexpected Tongo audit ciphertext length".to_string())
    })?;
    Ok((ciphertext, nonce_bytes))
}

/// Decrypt a Tongo audit hint with the auditor's key and its operation context.
pub fn decrypt_as_auditor_with_context(
    ciphertext: &[u8; CIPHERTEXT_SIZE],
    cipher_nonce: &[u8; 24],
    auditor_private_key: &Felt,
    user_public_key: &ProjectivePoint,
    account_nonce: &Felt,
    tongo_address: &Felt,
) -> Result<u128> {
    let nonce = checked_account_nonce(account_nonce)?;
    let key = derive_tongo_audit_key(auditor_private_key, user_public_key, nonce, tongo_address)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| KmsError::CryptoError("invalid Tongo audit key".to_string()))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(&XNonce::from(*cipher_nonce), ciphertext.as_ref())
            .map_err(|_| KmsError::CryptoError("Tongo audit decryption failed".to_string()))?,
    );
    if plaintext.len() != PLAINTEXT_SIZE {
        return Err(KmsError::CryptoError(
            "invalid Tongo audit plaintext length".to_string(),
        ));
    }
    let mut balance = [0u8; 4];
    balance.copy_from_slice(&plaintext[NOISE_SIZE..]);
    Ok(u128::from(u32::from_be_bytes(balance)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tongo_hint_roundtrip_and_context_binding() {
        let user_sk = Felt::from(42u64);
        let auditor_sk = Felt::from(123u64);
        let user_pk = StarkCurve::mul_generator(&user_sk);
        let auditor_pk = StarkCurve::mul_generator(&auditor_sk);
        let nonce = Felt::from(7u64);
        let address = Felt::from(0x1234u64);

        for balance in [0, u32::MAX as u128] {
            let (hint, cipher_nonce) =
                encrypt_for_auditor_with_context(balance, &user_sk, &auditor_pk, &nonce, &address)
                    .unwrap();
            assert_eq!(
                decrypt_as_auditor_with_context(
                    &hint,
                    &cipher_nonce,
                    &auditor_sk,
                    &user_pk,
                    &nonce,
                    &address,
                )
                .unwrap(),
                balance
            );
            assert!(decrypt_as_auditor_with_context(
                &hint,
                &cipher_nonce,
                &auditor_sk,
                &user_pk,
                &Felt::from(8u64),
                &address,
            )
            .is_err());
            assert!(decrypt_as_auditor_with_context(
                &hint,
                &cipher_nonce,
                &auditor_sk,
                &user_pk,
                &nonce,
                &Felt::from(0x1235u64),
            )
            .is_err());
        }

        assert!(encrypt_for_auditor_with_context(
            u32::MAX as u128 + 1,
            &user_sk,
            &auditor_pk,
            &nonce,
            &address,
        )
        .is_err());
        let too_large_nonce = Felt::from(u64::MAX) + Felt::ONE;
        assert!(encrypt_for_auditor_with_context(
            0,
            &user_sk,
            &auditor_pk,
            &too_large_nonce,
            &address,
        )
        .is_err());
    }
}
