//! Mnemonic phrase generation and validation.
//!
//! # Memory
//!
//! The entropy, the phrase this module builds, the NFKD passphrase, and every
//! PBKDF2 buffer live in `Zeroizing` values or the crate's wiped HMAC
//! (`zeroizing_hmac`). `bip39` makes unwiped copies of the entropy and word
//! indices while it encodes or parses (its `zeroize` feature wipes only the
//! final `Mnemonic`), so each public function here runs that work in a nested
//! frame, then overwrites 32 KiB of the stack below it. Not covered: heap
//! copies made by NFKD (`bip39`'s of a non-ASCII phrase, and the normaliser's
//! buffer for long combining sequences), copies the compiler makes when it
//! moves a value, register spills, and stack deeper than the scrub. A seed or
//! phrase returned by value is the caller's to wipe.

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
/// - OS entropy source unavailable (`CryptoError`)
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
    getrandom::fill(entropy.as_mut_slice())
        .map_err(|e| KmsError::CryptoError(format!("OS entropy source unavailable: {e}")))?;

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
mod tests;
