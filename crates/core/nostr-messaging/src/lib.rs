//! Nostr-inspired private messaging primitives (NIP-17/44 style).
//! Built for Ghoul: secp256k1 ECDH + HKDF-SHA256 + ChaCha20 + HMAC-SHA256.
//! Provides simple encrypt/decrypt helpers and key derivation.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use k256::{
    ecdh::diffie_hellman,
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
#[cfg(feature = "test-utils")]
use std::sync::{LazyLock, Mutex};
use thiserror::Error;
#[cfg(feature = "test-utils")]
use zeroize::Zeroize;

/// Protocol version (matches NIP-44 v2 layout expectations).
pub const VERSION: u8 = 2;

type HmacSha256 = Hmac<Sha256>;

#[cfg(feature = "test-utils")]
const PARITY_DOMAIN: &[u8] = b"kms-parity-v1";

#[cfg(feature = "test-utils")]
#[derive(Debug, Clone)]
struct DeterministicRngState {
    seed: [u8; 32],
    stream: Vec<u8>,
    counter: u64,
    block: [u8; 32],
    block_offset: usize,
}

#[cfg(feature = "test-utils")]
impl Zeroize for DeterministicRngState {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.stream.zeroize();
        self.block.zeroize();
        self.counter = 0;
        self.block_offset = 0;
    }
}

#[cfg(feature = "test-utils")]
impl Drop for DeterministicRngState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "test-utils")]
impl DeterministicRngState {
    fn new(seed: [u8; 32], stream: &[u8]) -> Self {
        Self {
            seed,
            stream: stream.to_vec(),
            counter: 0,
            block: [0u8; 32],
            block_offset: 32,
        }
    }

    fn refill_block(&mut self) {
        let mut hasher = sha2::Sha256::new();
        hasher.update(PARITY_DOMAIN);
        hasher.update(&self.stream);
        hasher.update(self.seed);
        hasher.update(self.counter.to_be_bytes());
        let digest = hasher.finalize();
        self.block.copy_from_slice(&digest);
        self.block_offset = 0;
        self.counter = self.counter.wrapping_add(1);
    }

    fn fill(&mut self, out: &mut [u8]) {
        let mut written = 0usize;
        while written < out.len() {
            if self.block_offset >= self.block.len() {
                self.refill_block();
            }

            let available = self.block.len() - self.block_offset;
            let needed = out.len() - written;
            let chunk = available.min(needed);
            out[written..written + chunk]
                .copy_from_slice(&self.block[self.block_offset..self.block_offset + chunk]);
            self.block_offset += chunk;
            written += chunk;
        }
    }
}

#[cfg(feature = "test-utils")]
static DETERMINISTIC_RNG: LazyLock<Mutex<Option<DeterministicRngState>>> =
    LazyLock::new(|| Mutex::new(None));

/// Enables deterministic parity RNG for operations that require randomness.
#[cfg(feature = "test-utils")]
pub fn set_deterministic_rng(seed: [u8; 32], stream: &[u8]) {
    let mut guard = DETERMINISTIC_RNG.lock().expect("rng mutex poisoned");
    *guard = Some(DeterministicRngState::new(seed, stream));
}

/// Clears deterministic parity RNG and restores system randomness.
#[cfg(feature = "test-utils")]
pub fn clear_deterministic_rng() {
    let mut guard = DETERMINISTIC_RNG.lock().expect("rng mutex poisoned");
    *guard = None;
}

fn fill_random_bytes(out: &mut [u8]) {
    #[cfg(feature = "test-utils")]
    {
        let mut guard = DETERMINISTIC_RNG.lock().expect("rng mutex poisoned");
        if let Some(state) = guard.as_mut() {
            state.fill(out);
            return;
        }
        drop(guard);
    }

    let mut rng = rand::thread_rng();
    rng.fill_bytes(out);
}

#[derive(Debug, Error)]
pub enum NostrError {
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("invalid key format")]
    InvalidKey,
    #[error("invalid payload")]
    InvalidPayload,
    #[error("mac verification failed")]
    MacMismatch,
}

fn decode_secret(hex_str: &str) -> Result<SecretKey, NostrError> {
    let bytes =
        hex::decode(strip_0x(hex_str)).map_err(|e| NostrError::InvalidHex(e.to_string()))?;
    SecretKey::from_slice(&bytes).map_err(|_| NostrError::InvalidKey)
}

fn decode_public(hex_str: &str) -> Result<PublicKey, NostrError> {
    let bytes =
        hex::decode(strip_0x(hex_str)).map_err(|e| NostrError::InvalidHex(e.to_string()))?;
    PublicKey::from_sec1_bytes(&bytes).map_err(|_| NostrError::InvalidKey)
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

/// Derive a shared secret (32 bytes) using secp256k1 ECDH.
pub fn derive_shared_secret(
    sender_sk_hex: &str,
    receiver_pk_hex: &str,
) -> Result<[u8; 32], NostrError> {
    let sk = decode_secret(sender_sk_hex)?;
    let pk = decode_public(receiver_pk_hex)?;
    let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let bytes = shared.raw_secret_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_slice());
    Ok(out)
}

/// Derive public key (SEC1 compressed hex) from secret key.
pub fn derive_public_key(secret_hex: &str) -> Result<String, NostrError> {
    let sk = decode_secret(secret_hex)?;
    let pk: PublicKey = sk.public_key();
    Ok(format!("{:02x}", pk.to_encoded_point(true)))
}

/// Encrypt a message. Returns base64 payload: [version | nonce | ciphertext | mac].
pub fn encrypt_message(
    sender_sk_hex: &str,
    receiver_pk_hex: &str,
    plaintext: &[u8],
) -> Result<String, NostrError> {
    let shared = derive_shared_secret(sender_sk_hex, receiver_pk_hex)?;
    let (enc_key, mac_key) = derive_keys(&shared);

    let mut nonce = [0u8; 12];
    fill_random_bytes(&mut nonce);

    let mut cipher = ChaCha20::new(&enc_key.into(), &nonce.into());
    let mut ciphertext = plaintext.to_vec();
    cipher.apply_keystream(&mut ciphertext);

    let mac = compute_mac(&mac_key, VERSION, &nonce, &ciphertext);

    let mut out = Vec::with_capacity(1 + nonce.len() + ciphertext.len() + mac.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&mac);

    Ok(STANDARD.encode(out))
}

/// Decrypt a base64 payload produced by `encrypt_message`.
pub fn decrypt_message(
    receiver_sk_hex: &str,
    sender_pk_hex: &str,
    payload_b64: &str,
) -> Result<Vec<u8>, NostrError> {
    let data = STANDARD
        .decode(payload_b64)
        .map_err(|_| NostrError::InvalidPayload)?;

    if data.len() < 1 + 12 + 32 {
        return Err(NostrError::InvalidPayload);
    }

    let version = data[0];
    if version != VERSION {
        return Err(NostrError::InvalidPayload);
    }

    let nonce = &data[1..13];
    let mac_start = data.len().saturating_sub(32);
    let ciphertext = &data[13..mac_start];
    let mac_bytes = &data[mac_start..];

    let shared = derive_shared_secret(receiver_sk_hex, sender_pk_hex)?;
    let (enc_key, mac_key) = derive_keys(&shared);

    let expected_mac = compute_mac(&mac_key, version, nonce.try_into().unwrap(), ciphertext);
    if mac_bytes != expected_mac {
        return Err(NostrError::MacMismatch);
    }

    let mut cipher = ChaCha20::new(&enc_key.into(), nonce.into());
    let mut plaintext = ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext);
    Ok(plaintext)
}

fn derive_keys(shared: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; 64];
    hk.expand(b"nostr-nip44-v2", &mut okm).expect("hkdf expand");
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&okm[..32]);
    mac.copy_from_slice(&okm[32..]);
    (enc, mac)
}

fn compute_mac(mac_key: &[u8; 32], version: u8, nonce: &[u8; 12], ciphertext: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("hmac key");
    mac.update(&[version]);
    mac.update(nonce);
    mac.update(ciphertext);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Sample deterministic keys (do not use in production).
    const ALICE_SK: &str = "0x1c0b9a6c83c6b0cbe8eebf5a4e3e4c1e6b6a2f9c1a7b0c6d4f9e1b2c3d4e5f6a";
    const BOB_SK: &str = "0x2d1c0a9b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f";

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let alice_pk = derive_public_key(ALICE_SK).unwrap();
        let bob_pk = derive_public_key(BOB_SK).unwrap();

        let payload = encrypt_message(ALICE_SK, &bob_pk, b"hello nostr").unwrap();
        let decrypted = decrypt_message(BOB_SK, &alice_pk, &payload).unwrap();

        assert_eq!(decrypted, b"hello nostr");
    }

    #[test]
    fn tamper_fails_mac() {
        let alice_pk = derive_public_key(ALICE_SK).unwrap();
        let bob_pk = derive_public_key(BOB_SK).unwrap();
        let payload = encrypt_message(ALICE_SK, &bob_pk, b"secure message").unwrap();
        // Flip one byte in base64 string (safe: replace last char)
        let mut bytes = payload.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        let res = decrypt_message(BOB_SK, &alice_pk, &tampered);
        assert!(matches!(
            res,
            Err(NostrError::InvalidPayload) | Err(NostrError::MacMismatch)
        ));
    }

    #[test]
    fn derive_public_matches_k256() {
        let pk_hex = derive_public_key(ALICE_SK).unwrap();
        let pk = hex::decode(pk_hex.clone()).unwrap();
        let parsed = PublicKey::from_sec1_bytes(&pk).unwrap();
        assert_eq!(pk_hex, format!("{:02x}", parsed.to_encoded_point(true)));
    }
}
