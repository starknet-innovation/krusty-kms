//! RFC 4231 and RFC 5869 vectors, a differential check against the `hmac`
//! crate, and the compile-time wiping guarantees the helper relies on.

use super::*;
use sha2::Sha512;

/// RFC 4231 test cases 1-4: (key, data, HMAC-SHA-256, HMAC-SHA-512).
fn rfc_4231_cases() -> Vec<(Vec<u8>, Vec<u8>, &'static str, &'static str)> {
    vec![
        (
            vec![0x0b; 20],
            b"Hi There".to_vec(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?".to_vec(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        ),
        (
            vec![0xaa; 20],
            vec![0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
             bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        ),
        (
            (1..=25).collect(),
            vec![0xcd; 50],
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
             a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
        ),
    ]
}

#[test]
fn hmac_matches_rfc_4231() {
    for (key, data, sha256, sha512) in rfc_4231_cases() {
        assert_eq!(
            hex::encode(hmac::<Sha256, 32>(&key, &[&data]).unwrap().as_ref()),
            sha256
        );
        assert_eq!(
            hex::encode(hmac::<Sha512, 64>(&key, &[&data]).unwrap().as_ref()),
            sha512
        );
    }
}

#[test]
fn hmac_message_parts_concatenate() {
    let whole = hmac::<Sha256, 32>(b"Jefe", &[b"what do ya want for nothing?"]).unwrap();
    let split = hmac::<Sha256, 32>(b"Jefe", &[b"what do ya ", b"", b"want for nothing?"]).unwrap();
    assert_eq!(whole, split);
}

#[test]
fn hmac_matches_the_hmac_crate_up_to_one_block() {
    use ::hmac::{Hmac, KeyInit, Mac};
    let key: Vec<u8> = (0..=255u8).collect();
    let message = b"krusty shared HMAC differential message";
    for len in [0, 1, 12, 20, 32, 63, 64] {
        let mut expected = Hmac::<Sha256>::new_from_slice(&key[..len]).unwrap();
        expected.update(message);
        let actual = hmac::<Sha256, 32>(&key[..len], &[message]).unwrap();
        assert_eq!(&actual[..], &expected.finalize().into_bytes()[..], "{len}");
    }
    for len in [0, 12, 32, 64, 127, 128] {
        let mut expected = Hmac::<Sha512>::new_from_slice(&key[..len]).unwrap();
        expected.update(message);
        let actual = hmac::<Sha512, 64>(&key[..len], &[message]).unwrap();
        assert_eq!(&actual[..], &expected.finalize().into_bytes()[..], "{len}");
    }
}

#[test]
fn hmac_refuses_keys_longer_than_a_block_and_wrong_output_sizes() {
    // RFC 4231 test cases 6 and 7 use a 131-byte key; it is refused, not hashed.
    assert!(hmac::<Sha256, 32>(&[0xaa; 131], &[b"x"]).is_err());
    assert!(hmac::<Sha512, 64>(&[0xaa; 131], &[b"x"]).is_err());
    assert!(hmac::<Sha256, 32>(&[0xaa; 65], &[b"x"]).is_err());
    assert!(hmac::<Sha512, 64>(&[0xaa; 129], &[b"x"]).is_err());
    assert!(hmac::<Sha256, 64>(b"key", &[b"x"]).is_err());
    assert!(hmac::<Sha512, 32>(b"key", &[b"x"]).is_err());
}

#[test]
fn hkdf_expand_matches_rfc_5869() {
    // Test case 1: PRK from salt 0x00..0c and IKM 0x0b x 22.
    let salt: Vec<u8> = (0..=0x0c).collect();
    let prk = hmac::<Sha256, 32>(&salt, &[&[0x0b; 22]]).unwrap();
    assert_eq!(
        hex::encode(prk.as_ref()),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    let info: Vec<u8> = (0xf0..=0xf9).collect();
    assert_eq!(
        hex::encode(hkdf_sha256_expand::<42>(&prk, &info).unwrap().as_ref()),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );

    // Test case 3: empty salt and info.
    let prk = hmac::<Sha256, 32>(&[], &[&[0x0b; 22]]).unwrap();
    assert_eq!(
        hex::encode(prk.as_ref()),
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    );
    assert_eq!(
        hex::encode(hkdf_sha256_expand::<42>(&prk, &[]).unwrap().as_ref()),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn hkdf_expand_is_a_prefix_and_bounded() {
    let prk = [7u8; 32];
    let long = hkdf_sha256_expand::<76>(&prk, b"info").unwrap();
    let short = hkdf_sha256_expand::<32>(&prk, b"info").unwrap();
    assert_eq!(&long[..32], &short[..]);
    assert!(hkdf_sha256_expand::<{ 255 * 32 }>(&prk, b"info").is_ok());
    assert!(hkdf_sha256_expand::<{ 255 * 32 + 1 }>(&prk, b"info").is_err());
}

#[test]
fn hash_states_wipe_themselves_on_drop() {
    // Fails to compile if sha2's `zeroize` feature is dropped.
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<Sha256>();
    assert_zeroize_on_drop::<Sha512>();
    assert_zeroize_on_drop::<Zeroizing<[u8; 64]>>();
}

#[test]
fn pbkdf2_sha512_matches_python_hashlib() {
    // Vectors from CPython's `hashlib.pbkdf2_hmac("sha512", ...)`. The last two
    // sit on either side of the one-block password limit, where the password
    // stops being the HMAC key and its SHA-512 hash takes over.
    type Case<'a> = (&'a [u8], &'a [&'a [u8]], u32, &'a str);
    let cases: [Case; 4] = [
        (
            b"password",
            &[b"salt"],
            1,
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252\
          c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
        ),
        (
            b"password",
            &[b"sa", b"lt"],
            2048,
            "91be23564f09fc855c82ce84a223ebe7d63d8b49d69372593a0d9ed39e143c83\
          e1ab2f722a5ddb969feefc88403f7e2afe1afb8b2f0e6b20add0fb7b28368807",
        ),
        (
            &[b'p'; 129],
            &[b"mnemonic", b"salt"],
            2048,
            "11b11ac66534b3dc649bfe75a7d2cace13f58de19f85f5a3909f3204588fbf48\
          a5393110450ed22fe1097bf6813125e1c6833a8b83cc2f416164947ee9ce10d7",
        ),
        (
            &[b'p'; 128],
            &[b"mnemonic", b"salt"],
            2048,
            "08b718151edd9e7dd75296cb612a951f531acc6529da263939f71a7b623142f7\
          c900aefea3e667064f4ba54a52da3999e90b00901d03f4b317f9f79c094dda56",
        ),
    ];
    for (password, salt, rounds, expected) in cases {
        let got = pbkdf2_sha512(password, salt, rounds).unwrap();
        assert_eq!(
            hex::encode(&got[..]),
            expected,
            "{} byte password",
            password.len()
        );
    }
}
