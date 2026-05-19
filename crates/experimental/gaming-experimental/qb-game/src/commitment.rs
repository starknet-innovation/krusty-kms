//! Commitment scheme for play selection.
//!
//! Uses a hash-based commitment for simplicity:
//! - Commit: C = H(play_index || salt)
//! - Reveal: Send (play_index, salt), verify H(play_index || salt) == C
//!
//! This provides:
//! - Hiding: Cannot determine play from commitment without salt
//! - Binding: Cannot open to a different play (hash collision resistant)

use rand_core::TryRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::{DefensiveCoverage, OffensivePlay};

/// Salt length in bytes.
const SALT_LEN: usize = 32;

/// Commitment to a play selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayCommitment {
    /// The commitment hash.
    pub hash: [u8; 32],
}

impl PlayCommitment {
    /// Create a commitment from raw hash bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { hash: bytes }
    }

    /// Convert to hex string for display.
    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self { hash: arr })
    }
}

/// Opening data for a commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentOpening {
    /// The play index (0-11 for offense, 0-9 for defense).
    pub play_index: u8,
    /// Random salt used in the commitment.
    pub salt: [u8; SALT_LEN],
}

impl CommitmentOpening {
    /// Create a new opening with a random salt.
    pub fn new_random(play_index: u8) -> Self {
        let mut salt = [0u8; SALT_LEN];
        rand_core::OsRng
            .try_fill_bytes(&mut salt)
            .expect("OS entropy source unavailable");
        Self { play_index, salt }
    }

    /// Create an opening with a specific salt.
    pub fn new(play_index: u8, salt: [u8; SALT_LEN]) -> Self {
        Self { play_index, salt }
    }
}

/// Compute a commitment hash.
fn compute_commitment_hash(play_index: u8, salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([play_index]);
    hasher.update(salt);
    hasher.finalize().into()
}

/// Create a commitment to an offensive play.
pub fn commit_offensive_play(play: OffensivePlay) -> (PlayCommitment, CommitmentOpening) {
    let opening = CommitmentOpening::new_random(play.to_index() as u8);
    let hash = compute_commitment_hash(opening.play_index, &opening.salt);
    (PlayCommitment { hash }, opening)
}

/// Create a commitment to a defensive coverage.
pub fn commit_defensive_coverage(
    coverage: DefensiveCoverage,
) -> (PlayCommitment, CommitmentOpening) {
    let opening = CommitmentOpening::new_random(coverage.to_index() as u8);
    let hash = compute_commitment_hash(opening.play_index, &opening.salt);
    (PlayCommitment { hash }, opening)
}

/// Verify a commitment opening.
pub fn verify_commitment(commitment: &PlayCommitment, opening: &CommitmentOpening) -> bool {
    let computed_hash = compute_commitment_hash(opening.play_index, &opening.salt);
    commitment.hash == computed_hash
}

/// Verify and extract an offensive play from a commitment opening.
pub fn open_offensive_play(
    commitment: &PlayCommitment,
    opening: &CommitmentOpening,
) -> Option<OffensivePlay> {
    if !verify_commitment(commitment, opening) {
        return None;
    }
    OffensivePlay::from_index(opening.play_index as usize)
}

/// Verify and extract a defensive coverage from a commitment opening.
pub fn open_defensive_coverage(
    commitment: &PlayCommitment,
    opening: &CommitmentOpening,
) -> Option<DefensiveCoverage> {
    if !verify_commitment(commitment, opening) {
        return None;
    }
    DefensiveCoverage::from_index(opening.play_index as usize)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_roundtrip_offense() {
        for play in OffensivePlay::ALL {
            let (commitment, opening) = commit_offensive_play(play);
            let recovered = open_offensive_play(&commitment, &opening).unwrap();
            assert_eq!(play, recovered);
        }
    }

    #[test]
    fn test_commitment_roundtrip_defense() {
        for coverage in DefensiveCoverage::ALL {
            let (commitment, opening) = commit_defensive_coverage(coverage);
            let recovered = open_defensive_coverage(&commitment, &opening).unwrap();
            assert_eq!(coverage, recovered);
        }
    }

    #[test]
    fn test_commitment_hiding() {
        // Same play with different salts should produce different commitments
        let (c1, _) = commit_offensive_play(OffensivePlay::Slant);
        let (c2, _) = commit_offensive_play(OffensivePlay::Slant);
        assert_ne!(
            c1.hash, c2.hash,
            "Different salts should produce different commitments"
        );
    }

    #[test]
    fn test_commitment_binding() {
        // Cannot open to wrong play
        let (commitment, mut bad_opening) = commit_offensive_play(OffensivePlay::Slant);

        // Try to open to a different play
        bad_opening.play_index = OffensivePlay::HailMary.to_index() as u8;
        assert!(
            open_offensive_play(&commitment, &bad_opening).is_none(),
            "Should not be able to open to different play"
        );
    }

    #[test]
    fn test_wrong_salt_fails() {
        let (commitment, mut bad_opening) = commit_offensive_play(OffensivePlay::Slant);

        // Modify salt
        bad_opening.salt[0] ^= 0xFF;
        assert!(
            !verify_commitment(&commitment, &bad_opening),
            "Wrong salt should fail verification"
        );
    }

    #[test]
    fn test_commitment_hex_roundtrip() {
        let (commitment, _) = commit_offensive_play(OffensivePlay::QbSneak);
        let hex_str = commitment.to_hex();
        let recovered = PlayCommitment::from_hex(&hex_str).unwrap();
        assert_eq!(commitment, recovered);
    }

    #[test]
    fn test_commitment_different_plays() {
        // Different plays should (with overwhelming probability) produce different commitments
        let (c1, _) = commit_offensive_play(OffensivePlay::QbSneak);
        let (c2, _) = commit_offensive_play(OffensivePlay::HailMary);
        assert_ne!(c1.hash, c2.hash);
    }

    #[test]
    fn test_invalid_play_index_fails() {
        let (commitment, _) = commit_offensive_play(OffensivePlay::Slant);
        let bad_opening = CommitmentOpening::new_random(99); // Invalid index
        assert!(open_offensive_play(&commitment, &bad_opening).is_none());
    }
}
