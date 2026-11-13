//! Native keystore ciphertext validation at the public import boundary.

use krusty_kms::keystore::decrypt_keystore;

#[test]
fn short_ciphertext_is_rejected_as_malformed_input() {
    let mut keystore = serde_json::json!({
        "version": 1,
        "crypto": {
            "kdfparams": {"salt": hex::encode([0xabu8; 16]), "n": 1024},
            "nonce": hex::encode([0x11u8; 24]),
            "ciphertext": "",
        }
    });
    for len in [0usize, 15] {
        keystore["crypto"]["ciphertext"] = hex::encode(vec![0x22u8; len]).into();
        let error = decrypt_keystore(&keystore.to_string(), "synthetic-password").unwrap_err();
        assert!(
            format!("{error:?}").contains("authentication tag"),
            "ciphertext len {len}: {error:?}"
        );
    }
}
