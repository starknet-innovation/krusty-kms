use super::*;

#[test]
fn test_generate_mnemonic_12_words() {
    let mnemonic = generate_mnemonic(12).unwrap();
    assert_eq!(mnemonic.split_whitespace().count(), 12);
    assert!(validate_mnemonic(&mnemonic).is_ok());
}

#[test]
fn test_phrase_buffer_never_reallocates() {
    // `generate_mnemonic` sizes its buffer at 9 bytes per word.
    assert!(bip39::Language::English
        .word_list()
        .iter()
        .all(|w| w.len() <= 8));
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
            for (case, passphrase) in passphrases.iter().enumerate() {
                // Name the case, not the secret inputs, on failure.
                assert_eq!(
                    mnemonic_to_seed(&phrase, passphrase).unwrap(),
                    reference.to_seed(*passphrase),
                    "entropy {len} bytes, fill {fill:#04x}, passphrase case {case}"
                );
            }
        }
    }
    assert!(short && long, "cover both sides of the 128-byte key limit");
}

#[test]
fn non_canonical_spelling_derives_the_canonical_seed() {
    let canonical = "habit hope tip crystal because grunt nation idea electric witness alert like";
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
