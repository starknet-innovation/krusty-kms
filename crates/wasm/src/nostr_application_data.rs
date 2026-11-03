//! Mnemonic-bound NIP-59 application-data operations.
//!
//! The mnemonic, passphrase, and plaintext content are taken as owned strings
//! and wiped when the call returns. Opened content is returned to the JS heap
//! (see [`crate`]).

use crate::error::from_sdk_result;
use serde_json::json;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Derive the Nostr key; the caller holds the mnemonic and passphrase in
/// `Zeroizing`, and the returned keypair wipes itself on drop.
fn nostr_private_key(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
    passphrase: Option<&str>,
) -> Result<krusty_kms::NostrKeyPair, JsValue> {
    from_sdk_result(krusty_kms::derive_nostr_keypair(
        mnemonic,
        address_index,
        account_index,
        passphrase,
    ))
    .map_err(JsValue::from)
}

/// Creates a NIP-59 gift wrap without exposing the derived Nostr private key.
#[wasm_bindgen(js_name = "wrapNostrApplicationData")]
pub fn wrap_nostr_application_data(
    mnemonic: String,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
    recipient_public_key: &str,
    identifier: &str,
    content: String,
) -> Result<String, JsValue> {
    let (mnemonic, passphrase) = (Zeroizing::new(mnemonic), passphrase.map(Zeroizing::new));
    let content = Zeroizing::new(content);
    let passphrase_ref = passphrase.as_deref().map(String::as_str);
    let keypair = nostr_private_key(&mnemonic, address_index, account_index, passphrase_ref)?;
    from_sdk_result(krusty_kms::wrap_nostr_application_data_at(
        &keypair.private_key,
        recipient_public_key,
        identifier,
        &content,
        (js_sys::Date::now() / 1_000.0) as u64,
    ))
    .map_err(JsValue::from)
}

/// Opens a NIP-59 gift wrap without exposing the derived Nostr private key.
#[wasm_bindgen(js_name = "openNostrApplicationData")]
pub fn open_nostr_application_data(
    mnemonic: String,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
    event_json: &str,
) -> Result<String, JsValue> {
    let (mnemonic, passphrase) = (Zeroizing::new(mnemonic), passphrase.map(Zeroizing::new));
    let passphrase_ref = passphrase.as_deref().map(String::as_str);
    let keypair = nostr_private_key(&mnemonic, address_index, account_index, passphrase_ref)?;
    let opened = from_sdk_result(krusty_kms::open_nostr_application_data(
        &keypair.private_key,
        event_json,
    ))
    .map_err(JsValue::from)?;
    Ok(json!({
        "content": opened.content,
        "identifier": opened.identifier,
        "senderPublicKey": opened.sender_public_key,
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    const MNEMONIC: &str =
        "habit hope tip crystal because grunt nation idea electric witness alert like";

    #[wasm_bindgen_test]
    fn mnemonic_bound_gift_wrap_round_trip() {
        let recipient =
            crate::account::derive_nostr_public_key(MNEMONIC.into(), 1, 0, None).unwrap();
        let event = wrap_nostr_application_data(
            MNEMONIC.into(),
            0,
            0,
            None,
            &recipient.public_key,
            "mc-wallet.multisig",
            "payload".into(),
        )
        .unwrap();

        let opened = open_nostr_application_data(MNEMONIC.into(), 1, 0, None, &event).unwrap();

        assert!(opened.contains(r#""identifier":"mc-wallet.multisig""#));
        assert!(opened.contains(r#""content":"payload""#));
        assert!(open_nostr_application_data(MNEMONIC.into(), 0, 0, None, &event).is_err());
    }
}
