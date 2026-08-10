//! Signed coordination envelopes: signing hash coverage, signature
//! verification, and the wire-format version discriminator.

use super::{address, call, confirmation_notice, test_signing_key};
use crate::multisig::types::validate_envelope_payload;
use crate::multisig::{
    coordination_message_hash, MultisigCall, MultisigCoordinationEnvelope,
    MultisigCoordinationMessage, MultisigProposal, MultisigSignerNotice,
    SignedMultisigCoordinationMessage, MULTISIG_COORDINATION_SCHEMA_VERSION,
};
use crate::wallet::utils::rs_felt_to_core;
use krusty_kms_common::{ChainId, KmsError};
use starknet_types_core::felt::Felt;

#[test]
fn test_coordination_message_hash_binds_every_field() {
    let base = confirmation_notice(3);
    let base_hash = coordination_message_hash(&base);

    // Same fields under a different kind must hash differently.
    let revocation = MultisigCoordinationMessage::Revocation(MultisigSignerNotice::new(
        address(1),
        ChainId::Sepolia,
        Felt::from(42u64),
        address(3),
    ));
    assert_ne!(base_hash, coordination_message_hash(&revocation));

    // Claimed actor is bound.
    assert_ne!(
        base_hash,
        coordination_message_hash(&confirmation_notice(4))
    );

    // Chain is bound.
    let other_chain = MultisigCoordinationMessage::Confirmation(MultisigSignerNotice::new(
        address(1),
        ChainId::Mainnet,
        Felt::from(42u64),
        address(3),
    ));
    assert_ne!(base_hash, coordination_message_hash(&other_chain));

    // Deterministic for identical messages.
    assert_eq!(
        base_hash,
        coordination_message_hash(&confirmation_notice(3))
    );
}

#[test]
fn test_coordination_message_hash_binds_proposer_and_memo() {
    let proposal = |proposer: u64, memo: Option<&str>| {
        MultisigCoordinationMessage::Proposal(MultisigProposal::new(
            address(1),
            ChainId::Sepolia,
            vec![call()],
            Felt::from(99u64),
            address(proposer),
            memo.map(str::to_string),
        ))
    };

    let base_hash = coordination_message_hash(&proposal(2, Some("rotate signer")));
    // The reviewer-flagged attribution fields are covered by the hash.
    assert_ne!(
        base_hash,
        coordination_message_hash(&proposal(3, Some("rotate signer")))
    );
    assert_ne!(
        base_hash,
        coordination_message_hash(&proposal(2, Some("drain treasury")))
    );
    assert_ne!(base_hash, coordination_message_hash(&proposal(2, None)));
    assert_ne!(
        coordination_message_hash(&proposal(2, None)),
        coordination_message_hash(&proposal(2, Some("")))
    );
}

#[test]
fn test_signed_message_sign_and_verify_roundtrip() {
    let key = test_signing_key(0x1234);
    let public_key = rs_felt_to_core(key.verifying_key().scalar());

    let signed =
        SignedMultisigCoordinationMessage::sign_with_stark_key(confirmation_notice(3), &key)
            .unwrap();
    assert_eq!(signed.version, MULTISIG_COORDINATION_SCHEMA_VERSION);
    assert_eq!(signed.claimed_actor(), address(3));
    signed.verify_with_stark_public_key(public_key).unwrap();

    // Survives a JSON wire roundtrip.
    let json = serde_json::to_string(&signed).unwrap();
    let roundtrip: SignedMultisigCoordinationMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip, signed);
    roundtrip.verify_with_stark_public_key(public_key).unwrap();
}

#[test]
fn test_signed_message_rejects_tampering_and_wrong_key() {
    let key = test_signing_key(0x1234);
    let public_key = rs_felt_to_core(key.verifying_key().scalar());

    let signed =
        SignedMultisigCoordinationMessage::sign_with_stark_key(confirmation_notice(3), &key)
            .unwrap();

    // A coordinator swapping the claimed signer invalidates the signature.
    let mut forged_actor = signed.clone();
    forged_actor.message = confirmation_notice(4);
    assert!(forged_actor
        .verify_with_stark_public_key(public_key)
        .is_err());

    // Reinterpreting a confirmation as a revocation invalidates it too.
    let mut forged_kind = signed.clone();
    if let MultisigCoordinationMessage::Confirmation(notice) = signed.message.clone() {
        forged_kind.message = MultisigCoordinationMessage::Revocation(notice);
    }
    assert!(forged_kind
        .verify_with_stark_public_key(public_key)
        .is_err());

    // A different key's signature does not verify.
    let other_key = test_signing_key(0x5678);
    assert!(signed
        .verify_with_stark_public_key(rs_felt_to_core(other_key.verifying_key().scalar()))
        .is_err());
}

#[test]
fn test_offline_verify_rejects_tampered_proposal_batch() {
    // The signing hash covers calls/salt only through transaction_id, so a
    // coordinator can swap the batch while keeping the id and signature intact
    // and the signature still verifies. Offline verification must recompute
    // the id, or it would attribute an attacker's calls to the signer.
    let key = test_signing_key(0x1234);
    let public_key = rs_felt_to_core(key.verifying_key().scalar());
    let proposal = MultisigProposal::new(
        address(1),
        ChainId::Sepolia,
        vec![call()],
        Felt::from(99u64),
        address(2),
        None,
    );
    let signed = SignedMultisigCoordinationMessage::sign_with_stark_key(
        MultisigCoordinationMessage::Proposal(proposal.clone()),
        &key,
    )
    .unwrap();
    signed.verify_with_stark_public_key(public_key).unwrap();

    let mut tampered = proposal;
    tampered.calls = vec![MultisigCall::new(
        address(0xbad),
        Felt::from(0x666u64),
        vec![Felt::from(1u64)],
    )];
    tampered.salt = Felt::from(1234u64);
    // transaction_id and signature deliberately left untouched.
    let forged = SignedMultisigCoordinationMessage {
        message: MultisigCoordinationMessage::Proposal(tampered),
        ..signed
    };
    assert!(matches!(
        forged.verify_with_stark_public_key(public_key),
        Err(KmsError::MultisigError(_))
    ));
    assert!(forged.validate_structure().is_err());
}

#[test]
fn test_signed_message_structure_validation() {
    let key = test_signing_key(0x1234);
    let mut signed =
        SignedMultisigCoordinationMessage::sign_with_stark_key(confirmation_notice(3), &key)
            .unwrap();
    signed.validate_structure().unwrap();

    signed.version = 2;
    assert!(signed.validate_structure().is_err());

    assert!(SignedMultisigCoordinationMessage::new(confirmation_notice(3), vec![]).is_err());
}

#[test]
fn test_envelope_serde_distinguishes_signed_and_legacy() {
    let key = test_signing_key(0x1234);
    let signed =
        SignedMultisigCoordinationMessage::sign_with_stark_key(confirmation_notice(3), &key)
            .unwrap();

    let signed_json =
        serde_json::to_string(&MultisigCoordinationEnvelope::from(signed.clone())).unwrap();
    assert!(signed_json.contains("\"version\":1"));
    let parsed: MultisigCoordinationEnvelope = serde_json::from_str(&signed_json).unwrap();
    assert_eq!(parsed, MultisigCoordinationEnvelope::Signed(signed));

    // Legacy (schema version 0) payloads are the bare tagged message and still
    // parse, as the unsigned variant.
    let legacy_json = serde_json::to_string(&confirmation_notice(3)).unwrap();
    let parsed: MultisigCoordinationEnvelope = serde_json::from_str(&legacy_json).unwrap();
    assert_eq!(
        parsed,
        MultisigCoordinationEnvelope::Unsigned(confirmation_notice(3))
    );
    assert!(parsed.as_signed().is_none());
}

#[test]
fn test_envelope_deserialization_never_downgrades_versioned_payloads() {
    // A payload carrying `version` must be a well-formed signed envelope.
    // Deserializing these as `Unsigned` instead would let a coordinator strip
    // authentication and have the result accepted as a legacy hint.

    // Signature moved to the top level (signed shape destroyed).
    let flattened = r#"{"type":"confirmation",
        "multisig":"0x0000000000000000000000000000000000000000000000000000000000000001",
        "chain_id":"Sepolia",
        "transaction_id":"0x000000000000000000000000000000000000000000000000000000000000002a",
        "signer":"0x0000000000000000000000000000000000000000000000000000000000000003",
        "version":1,"signature":["0x1","0x2"]}"#;
    assert!(serde_json::from_str::<MultisigCoordinationEnvelope>(flattened).is_err());

    // Legacy message carrying an unsupported version.
    let stray_version = r#"{"type":"confirmation",
        "multisig":"0x0000000000000000000000000000000000000000000000000000000000000001",
        "chain_id":"Sepolia",
        "transaction_id":"0x000000000000000000000000000000000000000000000000000000000000002a",
        "signer":"0x0000000000000000000000000000000000000000000000000000000000000003",
        "version":99}"#;
    assert!(serde_json::from_str::<MultisigCoordinationEnvelope>(stray_version).is_err());

    // A well-formed envelope with an unsupported version still parses (so the
    // error names the version) and is rejected by validation.
    let key = test_signing_key(0x1234);
    let mut future_version =
        SignedMultisigCoordinationMessage::sign_with_stark_key(confirmation_notice(3), &key)
            .unwrap();
    future_version.version = 99;
    let json = serde_json::to_string(&MultisigCoordinationEnvelope::from(future_version)).unwrap();
    let parsed: MultisigCoordinationEnvelope = serde_json::from_str(&json).unwrap();
    assert!(validate_envelope_payload(&parsed).is_err());
}
