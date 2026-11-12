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
fn gift_wrap_metadata_exposes_replays_to_the_caller() {
    let recipient = hex::encode(nostr_public_key(&RECIPIENT).unwrap());
    let now = 1_800_000_000;
    let event =
        wrap_nostr_application_data_at(&SENDER, &recipient, "mc-wallet.multisig", "payload", now)
            .unwrap();
    let wrap: SignedEvent = serde_json::from_str(&event).unwrap();
    let first = open_nostr_application_data_with_metadata(&RECIPIENT, &event).unwrap();

    // Opening is stateless: a replayed wrap opens again with the same ids.
    assert_eq!(
        open_nostr_application_data_with_metadata(&RECIPIENT, &event).unwrap(),
        first
    );
    assert_eq!(first.wrap_id, wrap.id);
    assert_eq!(first.created_at, now);
    assert_eq!(first.data.content, "payload");

    // Re-wrapping the same seal changes the wrap id but not the rumor id.
    let seal_json = nostr_nip44::decrypt(
        &RECIPIENT,
        &decode_hex::<32>(&wrap.pubkey, "pk").unwrap(),
        &wrap.content,
    )
    .unwrap();
    let ephemeral = ephemeral_private_key().unwrap();
    let rewrap = signed_event(
        &ephemeral,
        now,
        GIFT_WRAP_KIND,
        vec![vec!["p".to_string(), recipient.clone()]],
        nostr_nip44::encrypt(
            &ephemeral,
            &decode_hex::<32>(&recipient, "pk").unwrap(),
            &seal_json,
        )
        .unwrap(),
    )
    .unwrap();
    let second = open_nostr_application_data_with_metadata(
        &RECIPIENT,
        &serde_json::to_string(&rewrap).unwrap(),
    )
    .unwrap();
    assert_ne!(second.wrap_id, first.wrap_id);
    assert_eq!(second.rumor_id, first.rumor_id);
}

const THIRD: [u8; 32] = [7; 32];

/// Seal `rumor_json` as `seal_signer` for `seal_to`, then gift-wrap it to RECIPIENT.
fn wrap_seal(seal_signer: &[u8; 32], seal_to: &[u8; 32], rumor_json: &str) -> String {
    let recipient_key = nostr_public_key(&RECIPIENT).unwrap();
    let seal_to = nostr_public_key(seal_to).unwrap();
    let content = nostr_nip44::encrypt(seal_signer, &seal_to, rumor_json).unwrap();
    let seal = signed_event(seal_signer, 1, SEAL_KIND, Vec::new(), content).unwrap();
    let ephemeral = ephemeral_private_key().unwrap();
    let content = nostr_nip44::encrypt(
        &ephemeral,
        &recipient_key,
        &serde_json::to_string(&seal).unwrap(),
    )
    .unwrap();
    let tags = vec![vec!["p".to_string(), hex::encode(recipient_key)]];
    serde_json::to_string(&signed_event(&ephemeral, 1, GIFT_WRAP_KIND, tags, content).unwrap())
        .unwrap()
}

fn rumor_json(author: &[u8; 32]) -> String {
    let tags = vec![vec!["d".to_string(), "mc-wallet.multisig".to_string()]];
    let author = hex::encode(nostr_public_key(author).unwrap());
    let rumor = unsigned_event(
        author,
        1,
        APPLICATION_DATA_KIND,
        tags,
        "payload".to_string(),
    )
    .unwrap();
    serde_json::to_string(&rumor).unwrap()
}

#[test]
fn gift_wrap_binds_the_returned_sender_to_the_seal_signer() {
    // Control: the honest shape opens and names SENDER.
    let opened = open_nostr_application_data(
        &RECIPIENT,
        &wrap_seal(&SENDER, &RECIPIENT, &rumor_json(&SENDER)),
    )
    .unwrap();
    assert_eq!(
        opened.sender_public_key,
        hex::encode(nostr_public_key(&SENDER).unwrap())
    );

    let refused = [
        // SENDER seals a rumor that claims a third party wrote it.
        (
            "third-party rumor author",
            wrap_seal(&SENDER, &RECIPIENT, &rumor_json(&THIRD)),
        ),
        // SENDER seals a rumor that claims the recipient wrote it.
        (
            "recipient as rumor author",
            wrap_seal(&SENDER, &RECIPIENT, &rumor_json(&RECIPIENT)),
        ),
        // A seal SENDER made for THIRD, re-wrapped to RECIPIENT.
        (
            "seal for another recipient",
            wrap_seal(&SENDER, &THIRD, &rumor_json(&SENDER)),
        ),
        // RECIPIENT's own seal to SENDER, reflected back to RECIPIENT.
        (
            "reflected own seal",
            wrap_seal(&RECIPIENT, &SENDER, &rumor_json(&RECIPIENT)),
        ),
    ];
    for (case, event) in refused {
        assert!(
            open_nostr_application_data(&RECIPIENT, &event).is_err(),
            "{case}"
        );
    }
}

#[test]
fn gift_wrap_refuses_a_signed_rumor() {
    let mut rumor: serde_json::Value = serde_json::from_str(&rumor_json(&SENDER)).unwrap();
    rumor["sig"] = serde_json::Value::String("00".repeat(64));
    let event = wrap_seal(&SENDER, &RECIPIENT, &rumor.to_string());
    assert!(open_nostr_application_data(&RECIPIENT, &event).is_err());
}
