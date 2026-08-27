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
