//! Mnemonic phrase generation and validation.
//!
//! # Memory
//!
//! The entropy, the phrase this module builds, the NFKD passphrase, and every
//! PBKDF2 buffer live in `Zeroizing` values or the crate's wiped HMAC
//! (`zeroizing_hmac`). `bip39` makes unwiped copies of the entropy and word
//! indices while it encodes or parses (its `zeroize` feature wipes only the
//! final `Mnemonic`), so each public function here runs that work in a
//! nested frame and then overwrites 32 KiB of the stack below it. Not covered: heap copies `bip39` makes when it NFKD-normalises a
//! phrase that is not already NFKD (only non-ASCII input), copies the
//! compiler makes when it moves a value, register spills, and stack
//! deeper than the scrub. A seed or phrase returned by value is the
//! caller's to wipe.

use crate::zeroizing_hmac::pbkdf2_sha512;
use bip39::Mnemonic;
use krusty_kms_common::{KmsError, Result};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

/// BIP-39 seed derivation: PBKDF2-HMAC-SHA512, 2048 rounds.
const PBKDF2_ROUNDS: u32 = 2048;

/// Stack overwritten after each `bip39` call. Its encode, parse, and our
/// PBKDF2 use a few KiB; the margin covers other targets and compilers.
// ponytail: fixed size; derive it from a measured high-water mark if a
// target with deeper frames turns up.
const STACK_SCRUB_BYTES: usize = 32 * 1024;

/// Run `f` one frame down, then overwrite the stack it left behind.
fn scrubbed<T>(f: impl FnOnce() -> T) -> T {
    let out = run_nested(f);
    scrub_stack();
    out
}

#[inline(never)]
fn run_nested<T>(f: impl FnOnce() -> T) -> T {
    f()
}

/// Called from the frame that called [`run_nested`], so its buffer lies on
/// the stack the nested call used. `zeroize` writes are volatile.
#[inline(never)]
fn scrub_stack() {
    let mut stack = [0u8; STACK_SCRUB_BYTES];
    stack.zeroize();
    core::hint::black_box(&stack);
}

fn invalid(e: bip39::Error) -> KmsError {
    KmsError::InvalidMnemonic(format!("{e:?}"))
}

/// Parse a phrase into a mnemonic that is wiped on drop.
///
/// `Zeroizing<Mnemonic>` needs `Mnemonic: Zeroize`, which only holds with the
/// `bip39/zeroize` feature, so this also pins that feature at compile time.
fn parse_mnemonic(phrase: &str) -> Result<Zeroizing<Mnemonic>> {
    phrase
        .parse::<Mnemonic>()
        .map(Zeroizing::new)
        .map_err(invalid)
}

/// The canonical phrase (words joined by single spaces), in a buffer sized
/// up front so it never reallocates and leaves a partial copy behind.
fn phrase_of(mnemonic: &Mnemonic) -> Zeroizing<String> {
    let len = mnemonic
        .words()
        .map(|w| w.len() + 1)
        .sum::<usize>()
        .saturating_sub(1);
    let mut phrase = Zeroizing::new(String::with_capacity(len));
    for (i, word) in mnemonic.words().enumerate() {
        if i > 0 {
            phrase.push(' ');
        }
        phrase.push_str(word);
    }
    phrase
}

/// NFKD form of `text`, sized up front for the same reason as [`phrase_of`].
fn nfkd(text: &str) -> Zeroizing<String> {
    let len = text.nfkd().map(char::len_utf8).sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    for c in text.nfkd() {
        out.push(c);
    }
    out
}

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
/// Returns [`KmsError`] if:
/// - Invalid word count (not 12, 15, 18, 21, or 24) (`InvalidMnemonic`)
///
/// # Panics
///
/// Panics if OS entropy is unavailable (catastrophic, non-recoverable).
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
            return Err(KmsError::InvalidMnemonic(
                "Word count must be 12, 15, 18, 21, or 24".to_string(),
            ))
        }
    };

    let mut entropy = Zeroizing::new(vec![0u8; entropy_size]);
    getrandom::fill(entropy.as_mut_slice()).expect("OS entropy source unavailable");

    // Moves the phrase's buffer out without copying it.
    mnemonic_from_entropy(&entropy).map(|mut phrase| std::mem::take(&mut *phrase))
}

/// Encode BIP-39 entropy (16 to 32 bytes, a multiple of 4) as an English
/// phrase. See the module's Memory section for what is wiped.
///
/// # Errors
///
/// `InvalidMnemonic` if the entropy length is not one BIP-39 accepts.
pub fn mnemonic_from_entropy(entropy: &[u8]) -> Result<Zeroizing<String>> {
    scrubbed(|| {
        let mnemonic = Mnemonic::from_entropy(entropy)
            .map(Zeroizing::new)
            .map_err(invalid)?;
        Ok(phrase_of(&mnemonic))
    })
}

/// Validate a BIP-39 mnemonic phrase.
///
/// # Errors
///
/// Returns [`KmsError`] if:
/// - Mnemonic phrase is invalid (`InvalidMnemonic`)
/// - Checksum verification fails (`InvalidMnemonic`)
///
/// # Cyclomatic Complexity: 1
pub fn validate_mnemonic(phrase: &str) -> Result<()> {
    scrubbed(|| parse_mnemonic(phrase).map(drop))
}

/// Convert mnemonic to seed bytes.
///
/// The seed is PBKDF2-HMAC-SHA512 over the canonical phrase, salted with
/// `"mnemonic"` and the NFKD passphrase, computed here in wiped buffers
/// rather than by `bip39`, whose PBKDF2 leaves its key pads on the stack.
///
/// # Arguments
/// * `mnemonic` - The mnemonic phrase
/// * `passphrase` - Optional passphrase (empty string for no passphrase)
///
/// # Errors
///
/// `InvalidMnemonic` if the phrase does not parse or its checksum fails.
///
/// # Cyclomatic Complexity: 1
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    scrubbed(|| {
        let phrase = phrase_of(&*parse_mnemonic(mnemonic)?);
        let passphrase = nfkd(passphrase);
        let seed = pbkdf2_sha512(
            phrase.as_bytes(),
            &[b"mnemonic", passphrase.as_bytes()],
            PBKDF2_ROUNDS,
        )?;
        Ok(*seed)
    })
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
        let mnemonic =
            "habit hope tip crystal because grunt nation idea electric witness alert like";
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
        let mnemonic =
            "habit hope tip crystal because grunt nation idea electric witness alert like";
        let seed = mnemonic_to_seed(mnemonic, "").unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_mnemonic_to_seed_with_passphrase() {
        let mnemonic =
            "habit hope tip crystal because grunt nation idea electric witness alert like";
        let seed1 = mnemonic_to_seed(mnemonic, "").unwrap();
        let seed2 = mnemonic_to_seed(mnemonic, "mypassphrase").unwrap();
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_mnemonic_to_seed_invalid() {
        let result = mnemonic_to_seed("invalid mnemonic", "");
        assert!(result.is_err());
    }

    /// Trezor's python-mnemonic vectors (passphrase `TREZOR`), first and last.
    #[test]
    fn seed_matches_trezor_vectors() {
        let cases = [
            (
                "00000000000000000000000000000000",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
              1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e16\
              13912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
            ),
        ];
        for (entropy, seed) in cases {
            let phrase = mnemonic_from_entropy(&hex::decode(entropy).unwrap()).unwrap();
            let got = mnemonic_to_seed(&phrase, "TREZOR").unwrap();
            assert_eq!(hex::encode(got), seed, "{entropy}");
        }
    }

    /// Differential check against `bip39`'s own `to_seed`, over every word
    /// count, phrases on both sides of the one-block key limit, and
    /// passphrases that NFKD changes.
    #[test]
    fn seed_matches_bip39_to_seed() {
        let passphrases = [
            "",
            "TREZOR",
            "caf\u{e9}",
            "cafe\u{301}",
            "\u{fb01}",
            "\u{3042}\u{3099}",
            &"x".repeat(300),
        ];
        let (mut short, mut long) = (false, false);
        for len in [16usize, 20, 24, 28, 32] {
            for fill in [0x00u8, 0x5a, 0xa5, 0xc3, 0xff] {
                let entropy: Vec<u8> = (0..len)
                    .map(|i| fill ^ (i as u8).wrapping_mul(37))
                    .collect();
                let reference = Mnemonic::from_entropy(&entropy).unwrap();
                let phrase = mnemonic_from_entropy(&entropy).unwrap();
                assert_eq!(*phrase, reference.to_string());
                short |= phrase.len() <= 128;
                long |= phrase.len() > 128;
                for passphrase in passphrases {
                    assert_eq!(
                        mnemonic_to_seed(&phrase, passphrase).unwrap(),
                        reference.to_seed(passphrase),
                        "{} / {passphrase:?}",
                        *phrase
                    );
                }
            }
        }
        assert!(short && long, "cover both sides of the 128-byte key limit");
    }

    #[test]
    fn non_canonical_spelling_derives_the_canonical_seed() {
        let canonical =
            "habit hope tip crystal because grunt nation idea electric witness alert like";
        let spaced = format!(" {}\t", canonical.replace(' ', "  "));
        assert_eq!(
            mnemonic_to_seed(&spaced, "").unwrap(),
            mnemonic_to_seed(canonical, "").unwrap()
        );
    }

    #[test]
    fn mnemonic_from_entropy_rejects_bad_lengths() {
        assert!(mnemonic_from_entropy(&[0u8; 15]).is_err());
        assert!(mnemonic_from_entropy(&[0u8; 33]).is_err());
    }
}
