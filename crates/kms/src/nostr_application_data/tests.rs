use super::*;

const SENDER: [u8; 32] = [1; 32];
const RECIPIENT: [u8; 32] = [2; 32];

#[test]
fn gift_wrap_round_trip_authenticates_sender_and_content() {
    let recipient = hex::encode(nostr_public_key(&RECIPIENT).unwrap());
    let event = wrap_nostr_application_data(
        &SENDER,
        &recipient,
        "mc wallet.multisig",
        r#"{"kind":"intent"}"#,
    )
    .unwrap();
    let opened = open_nostr_application_data(&RECIPIENT, &event).unwrap();

    assert_eq!(
        opened.sender_public_key,
        hex::encode(nostr_public_key(&SENDER).unwrap())
    );
    assert_eq!(opened.identifier, "mc wallet.multisig");
    assert_eq!(opened.content, r#"{"kind":"intent"}"#);
    assert!(open_nostr_application_data(&SENDER, &event).is_err());
}

#[test]
fn gift_wrap_rejects_tampering_and_unbounded_inputs() {
    let recipient = hex::encode(nostr_public_key(&RECIPIENT).unwrap());
    let mut event =
        wrap_nostr_application_data(&SENDER, &recipient, "mc-wallet.multisig", "payload").unwrap();
    event.replace_range(event.len() - 2..event.len() - 1, "0");

    assert!(open_nostr_application_data(&RECIPIENT, &event).is_err());
    assert!(wrap_nostr_application_data(&SENDER, &recipient, "", "payload").is_err());
    assert!(wrap_nostr_application_data(
        &SENDER,
        &recipient,
        "mc-wallet.multisig",
        &"x".repeat(MAX_CONTENT_BYTES + 1)
    )
    .is_err());
    assert!(wrap_nostr_application_data(
        &SENDER,
        &recipient,
        "mc-wallet.multisig",
        &"\"".repeat(MAX_CONTENT_BYTES)
    )
    .unwrap_err()
    .to_string()
    .contains("nested envelope limit"));
}

#[test]
fn gift_wrap_errors_never_quote_decrypted_json() {
    let recipient_key = nostr_public_key(&RECIPIENT).unwrap();
    let recipient = hex::encode(recipient_key);
    let marker = "PLAINTEXT-MARKER";
    let wrap_inner = |seal_json: &str| {
        let ephemeral = ephemeral_private_key().unwrap();
        let content = nostr_nip44::encrypt(&ephemeral, &recipient_key, seal_json).unwrap();
        let tags = vec![vec!["p".to_string(), recipient.clone()]];
        let wrap = signed_event(&ephemeral, 1, GIFT_WRAP_KIND, tags, content).unwrap();
        serde_json::to_string(&wrap).unwrap()
    };

    // A seal that is not valid event JSON.
    let bad_seal = format!(r#"{{"id":"{marker}"}}"#);
    // A valid seal whose rumor has a string where a number belongs.
    let bad_rumor = format!(r#"{{"created_at":"{marker}"}}"#);
    let seal_content = nostr_nip44::encrypt(&SENDER, &recipient_key, &bad_rumor).unwrap();
    let seal = signed_event(&SENDER, 1, SEAL_KIND, Vec::new(), seal_content).unwrap();

    for event in [
        wrap_inner(&bad_seal),
        wrap_inner(&serde_json::to_string(&seal).unwrap()),
    ] {
        let error = open_nostr_application_data(&RECIPIENT, &event).unwrap_err();
        assert!(!format!("{error} {error:?}").contains(marker));
    }
}
