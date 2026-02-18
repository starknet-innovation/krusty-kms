//! Random value generation utilities for cryptographic operations.
//!
//! This module provides efficient random Felt generation, with support for
//! batch generation to amortize the overhead of creating thread-local RNGs.

use rand::RngCore;
use sha2::{Digest, Sha256};
use starknet_types_core::felt::Felt;
use std::sync::{LazyLock, Mutex};

const PARITY_DOMAIN: &[u8] = b"kms-parity-v1";

#[derive(Debug, Clone)]
struct DeterministicRngState {
    seed: [u8; 32],
    stream: Vec<u8>,
    counter: u64,
    block: [u8; 32],
    block_offset: usize,
}

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
        let mut hasher = Sha256::new();
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

static DETERMINISTIC_RNG: LazyLock<Mutex<Option<DeterministicRngState>>> =
    LazyLock::new(|| Mutex::new(None));

/// Enables deterministic parity RNG.
///
/// The RNG sequence is:
/// `SHA256("kms-parity-v1" || stream || seed || counter_be_u64)`.
pub fn set_deterministic_rng(seed: [u8; 32], stream: &[u8]) {
    let mut guard = DETERMINISTIC_RNG.lock().expect("rng mutex poisoned");
    *guard = Some(DeterministicRngState::new(seed, stream));
}

/// Clears deterministic parity RNG and restores system randomness.
pub fn clear_deterministic_rng() {
    let mut guard = DETERMINISTIC_RNG.lock().expect("rng mutex poisoned");
    *guard = None;
}

/// Fills a byte slice from either deterministic parity RNG (if enabled)
/// or cryptographic system randomness.
pub fn fill_random_bytes(out: &mut [u8]) {
    let mut guard = DETERMINISTIC_RNG.lock().expect("rng mutex poisoned");
    if let Some(state) = guard.as_mut() {
        state.fill(out);
        return;
    }

    drop(guard);
    let mut rng = rand::thread_rng();
    rng.fill_bytes(out);
}

/// Generate a single random Felt.
///
/// Creates a new thread-local RNG for this operation. For generating multiple
/// random values, prefer [`random_felts`] to amortize RNG overhead.
pub fn random_felt() -> Felt {
    let mut bytes = [0u8; 32];
    fill_random_bytes(&mut bytes);
    Felt::from_bytes_be(&bytes)
}

/// Generate multiple random Felts efficiently by reusing the RNG.
///
/// This is more efficient than calling [`random_felt`] multiple times because
/// it creates the thread-local RNG only once.
///
/// # Arguments
/// * `count` - Number of random Felts to generate
///
/// # Returns
/// Vector of `count` random Felts
pub fn random_felts(count: usize) -> Vec<Felt> {
    (0..count).map(|_| random_felt()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_felt_generates_different_values() {
        let r1 = random_felt();
        let r2 = random_felt();
        assert_ne!(r1, r2, "Random felts should be different");
    }

    #[test]
    fn test_random_felts_batch() {
        let values = random_felts(10);
        assert_eq!(values.len(), 10);

        // Check all values are different (with very high probability)
        for i in 0..values.len() {
            for j in (i + 1)..values.len() {
                assert_ne!(values[i], values[j], "Random felts should be unique");
            }
        }
    }

    #[test]
    fn test_random_felts_empty() {
        let values = random_felts(0);
        assert_eq!(values.len(), 0);
    }
}
