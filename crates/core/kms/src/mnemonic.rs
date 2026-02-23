//! Mnemonic phrase generation and validation.

use bip39::Mnemonic;
use ghoul_common::{GhoulError, Result};
use rand::Rng;

/// Generate a new BIP-39 mnemonic phrase.
///
/// # Arguments
/// * `word_count` - Number of words (12, 15, 18, 21, or 24)
///
/// # Returns
/// A new mnemonic phrase as a string
///
/// # Errors
///
/// Returns [`GhoulError`] if:
/// - Invalid word count (not 12, 15, 18, 21, or 24) (`InvalidMnemonic`)
/// - Entropy generation fails (`InvalidMnemonic`)
///
/// # Cyclomatic Complexity: 2 (early return for invalid input)
pub fn generate_mnemonic(word_count: usize) -> Result<String> {
    // Generate random entropy based on word count
    let entropy_size = match word_count {
        12 => 16,
        15 => 20,
        18 => 24,
        21 => 28,
        24 => 32,
        _ => {
            return Err(GhoulError::InvalidMnemonic(
                "Word count must be 12, 15, 18, 21, or 24".to_string(),
            ))
        }
    };

    let mut rng = rand::thread_rng();
    let entropy: Vec<u8> = (0..entropy_size).map(|_| rng.gen()).collect();

    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| GhoulError::InvalidMnemonic(format!("{e:?}")))?;

    Ok(mnemonic.to_string())
}

/// Validate a BIP-39 mnemonic phrase.
///
/// # Errors
///
/// Returns [`GhoulError`] if:
/// - Mnemonic phrase is invalid (`InvalidMnemonic`)
/// - Checksum verification fails (`InvalidMnemonic`)
///
/// # Cyclomatic Complexity: 1
pub fn validate_mnemonic(phrase: &str) -> Result<()> {
    // Use from_str via parse
    phrase
        .parse::<Mnemonic>()
        .map_err(|e| GhoulError::InvalidMnemonic(format!("{e:?}")))?;
    Ok(())
}

/// Convert mnemonic to seed bytes.
///
/// # Arguments
/// * `mnemonic` - The mnemonic phrase
/// * `passphrase` - Optional passphrase (empty string for no passphrase)
///
/// # Cyclomatic Complexity: 1
pub(crate) fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    let mnemonic_parsed: Mnemonic = mnemonic
        .parse()
        .map_err(|e| GhoulError::InvalidMnemonic(format!("{e:?}")))?;

    Ok(mnemonic_parsed.to_seed(passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic_12_words() {
        let mnemonic = generate_mnemonic(12).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
        assert!(validate_mnemonic(&mnemonic).is_ok());
    }

    #[test]
    fn test_generate_mnemonic_24_words() {
        let mnemonic = generate_mnemonic(24).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 24);
        assert!(validate_mnemonic(&mnemonic).is_ok());
    }

    #[test]
    fn test_validate_valid_mnemonic() {
        let mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";
        assert!(validate_mnemonic(mnemonic).is_ok());
    }

    #[test]
    fn test_validate_invalid_mnemonic() {
        let mnemonic = "invalid mnemonic phrase that should fail";
        assert!(validate_mnemonic(mnemonic).is_err());
    }

    #[test]
    fn test_invalid_word_count() {
        let result = generate_mnemonic(11);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_mnemonic_15_words() {
        let mnemonic = generate_mnemonic(15).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 15);
        assert!(validate_mnemonic(&mnemonic).is_ok());
    }

    #[test]
    fn test_generate_mnemonic_18_words() {
        let mnemonic = generate_mnemonic(18).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 18);
        assert!(validate_mnemonic(&mnemonic).is_ok());
    }

    #[test]
    fn test_generate_mnemonic_21_words() {
        let mnemonic = generate_mnemonic(21).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 21);
        assert!(validate_mnemonic(&mnemonic).is_ok());
    }

    #[test]
    fn test_mnemonic_to_seed() {
        let mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";
        let seed = mnemonic_to_seed(mnemonic, "").unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_mnemonic_to_seed_with_passphrase() {
        let mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";
        let seed1 = mnemonic_to_seed(mnemonic, "").unwrap();
        let seed2 = mnemonic_to_seed(mnemonic, "mypassphrase").unwrap();
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_mnemonic_to_seed_invalid() {
        let result = mnemonic_to_seed("invalid mnemonic", "");
        assert!(result.is_err());
    }
}
