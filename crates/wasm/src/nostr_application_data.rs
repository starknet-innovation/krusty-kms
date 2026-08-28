//! Mnemonic-bound NIP-59 application-data operations.

use crate::error::from_sdk_result;
use serde_json::json;
use wasm_bindgen::prelude::*;

fn nostr_private_key(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
) -> Result<krusty_kms::NostrKeyPair, JsValue> {
    from_sdk_result(krusty_kms::derive_nostr_keypair(
        mnemonic,
        address_index,
        account_index,
        passphrase.as_deref(),
    ))
    .map_err(JsValue::from)
}

/// Creates a NIP-59 gift wrap without exposing the derived Nostr private key.
#[wasm_bindgen(js_name = "wrapNostrApplicationData")]
pub fn wrap_nostr_application_data(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
    recipient_public_key: &str,
    identifier: &str,
    content: &str,
) -> Result<String, JsValue> {
    let keypair = nostr_private_key(mnemonic, address_index, account_index, passphrase)?;
    from_sdk_result(krusty_kms::wrap_nostr_application_data_at(
        &keypair.private_key,
        recipient_public_key,
        identifier,
        content,
        (js_sys::Date::now() / 1_000.0) as u64,
    ))
    .map_err(JsValue::from)
}

/// Opens a NIP-59 gift wrap without exposing the derived Nostr private key.
#[wasm_bindgen(js_name = "openNostrApplicationData")]
pub fn open_nostr_application_data(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
    event_json: &str,
) -> Result<String, JsValue> {
    let keypair = nostr_private_key(mnemonic, address_index, account_index, passphrase)?;
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
        let recipient = crate::account::derive_nostr_public_key(MNEMONIC, 1, 0, None).unwrap();
        let event = wrap_nostr_application_data(
            MNEMONIC,
            0,
            0,
            None,
            &recipient.public_key,
            "mc-wallet.multisig",
            "payload",
        )
        .unwrap();

        let opened = open_nostr_application_data(MNEMONIC, 1, 0, None, &event).unwrap();

        assert!(opened.contains(r#""identifier":"mc-wallet.multisig""#));
        assert!(opened.contains(r#""content":"payload""#));
        assert!(open_nostr_application_data(MNEMONIC, 0, 0, None, &event).is_err());
    }
}
