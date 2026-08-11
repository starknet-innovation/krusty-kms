use super::*;
use krusty_kms_common::ChainId;
use starknet_types_core::felt::Felt;

#[test]
fn felt_hex_normalizes_padding_and_case() {
    let short = FeltHex::parse("0xabc").unwrap();
    let padded = FeltHex::parse("0x0AbC").unwrap();

    assert_eq!(short, padded);
    assert_eq!(
        short.as_str(),
        "0x0000000000000000000000000000000000000000000000000000000000000abc"
    );
}

#[test]
fn felt_hex_roundtrips_through_felt() {
    let original = Felt::from(42u64);
    let hex = FeltHex::from_felt(original);

    assert_eq!(hex.to_felt(), original);
}

#[test]
fn hex_bytes_normalizes_prefix_and_case() {
    let bytes = HexBytes::parse("0xA0Bc").unwrap();

    assert_eq!(bytes.as_str(), "a0bc");
    assert_eq!(bytes.to_array::<2>().unwrap(), [0xa0, 0xbc]);
}

#[test]
fn secret_ref_rejects_blank_values() {
    assert_eq!(
        SecretRef::new("   ").unwrap_err(),
        DomainError::EmptyField {
            field: "secret_ref"
        }
    );
}

#[test]
fn cache_policy_requires_positive_ttl_and_capacity() {
    assert!(CachePolicy::new(0, 0, 10).is_err());
    assert!(CachePolicy::new(1_000, 0, 0).is_err());
    assert!(CachePolicy::new(1_000, 250, 64).is_ok());
}

#[test]
fn wait_policy_requires_positive_interval_and_timeout() {
    assert!(WaitPolicy::new(0, 1_000).is_err());
    assert!(WaitPolicy::new(100, 0).is_err());
    // Intervals below the RPC-flood floor are rejected (M-10).
    assert!(WaitPolicy::new(WaitPolicy::MIN_POLL_INTERVAL_MS - 1, 5_000).is_err());
    assert!(WaitPolicy::new(250, 5_000).is_ok());
}

#[test]
fn derivation_path_validates_coin_type_for_domain() {
    assert!(DerivationPath {
        coin_type: 9004,
        account_index: 0,
        address_index: 0,
    }
    .validate_for(KeyDomain::StarknetAccount)
    .is_ok());

    assert!(DerivationPath {
        coin_type: 5454,
        account_index: 0,
        address_index: 0,
    }
    .validate_for(KeyDomain::StarknetAccount)
    .is_err());
}

#[test]
fn nostr_event_sign_request_requires_32_byte_event_id() {
    let request = SignRequest::NostrEvent {
        secret: SecretRef::new("nostr-secret").unwrap(),
        derivation_path: DerivationPath {
            coin_type: 1237,
            account_index: 0,
            address_index: 7,
        },
        event_id: HexBytes::parse(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
    };

    assert!(request.validate().is_ok());

    let invalid = SignRequest::NostrEvent {
        secret: SecretRef::new("nostr-secret").unwrap(),
        derivation_path: DerivationPath {
            coin_type: 1237,
            account_index: 0,
            address_index: 7,
        },
        event_id: HexBytes::parse("abcd").unwrap(),
    };
    assert!(invalid.validate().is_err());
}

#[test]
fn stark_hash_sign_request_requires_matching_coin_type() {
    let request = SignRequest::StarkHash {
        secret: SecretRef::new("stark-secret").unwrap(),
        key_domain: StarkKeyDomain::StarknetAccount,
        derivation_path: DerivationPath {
            coin_type: 9004,
            account_index: 0,
            address_index: 1,
        },
        chain_id: ChainId::Sepolia,
        domain: StarkSignDomain::TransactionHash,
        hash: FeltHex::parse("0x1234").unwrap(),
        allow_raw_stark_hash: true,
    };

    assert!(request.validate().is_ok());

    let denied = SignRequest::StarkHash {
        secret: SecretRef::new("stark-secret").unwrap(),
        key_domain: StarkKeyDomain::StarknetAccount,
        derivation_path: DerivationPath {
            coin_type: 9004,
            account_index: 0,
            address_index: 1,
        },
        chain_id: ChainId::Sepolia,
        domain: StarkSignDomain::TransactionHash,
        hash: FeltHex::parse("0x1234").unwrap(),
        allow_raw_stark_hash: false,
    };
    assert!(denied.validate().is_err());

    let invalid = SignRequest::StarkHash {
        secret: SecretRef::new("stark-secret").unwrap(),
        key_domain: StarkKeyDomain::StarknetAccount,
        derivation_path: DerivationPath {
            coin_type: 5454,
            account_index: 0,
            address_index: 1,
        },
        chain_id: ChainId::Sepolia,
        domain: StarkSignDomain::TransactionHash,
        hash: FeltHex::parse("0x1234").unwrap(),
        allow_raw_stark_hash: true,
    };
    assert!(invalid.validate().is_err());
}

#[test]
fn secret_ref_rejects_raw_key_material() {
    let hex_key = "0x".to_string() + &"ab".repeat(32);
    assert!(SecretRef::new(hex_key).is_err());
    // Unpadded Stark scalar style (typical `expose_secret_hex` output).
    assert!(SecretRef::new("0x2a").is_err());
    assert!(SecretRef::new("0x".to_string() + &"ab".repeat(31)).is_err());
    assert!(SecretRef::new("ab".repeat(32)).is_err());
    assert!(SecretRef::new("ab".repeat(24)).is_err());
    assert!(SecretRef::new(
        "habit hope tip crystal because grunt nation idea electric witness alert like"
    )
    .is_err());
    assert!(SecretRef::new("wallet-1").is_ok());
    assert!(SecretRef::new("abc123").is_ok());
}

#[test]
fn secret_ref_rejects_zero_padded_key_material() {
    // Leading zeroes encode the same scalar, so padded forms must be
    // rejected just like the unpadded ones.
    assert!(SecretRef::new("0x0".to_string() + &"ab".repeat(32)).is_err());
    assert!(SecretRef::new("0x".to_string() + &"0".repeat(40) + &"ab".repeat(32)).is_err());
    assert!(SecretRef::new("0x".to_string() + &"0".repeat(63) + "2a").is_err());
    assert!(SecretRef::new("0".repeat(8) + &"ab".repeat(32)).is_err());
    // All-zero scalar stays rejected regardless of padding width.
    assert!(SecretRef::new("0x".to_string() + &"0".repeat(65)).is_err());
    // Opaque identifiers that merely start with a zero remain usable.
    assert!(SecretRef::new("0wallet").is_ok());
    assert!(SecretRef::new("0abc12").is_ok());
}

#[test]
fn stark_raw_message_requires_allow_raw_opt_in() {
    let denied = SignRequest::StarkRawMessage {
        secret: SecretRef::new("stark-secret").unwrap(),
        key_domain: StarkKeyDomain::StarknetAccount,
        derivation_path: DerivationPath {
            coin_type: 9004,
            account_index: 0,
            address_index: 1,
        },
        message: FeltHex::parse("0x1234").unwrap(),
        allow_raw_stark_hash: false,
    };
    assert!(denied.validate().is_err());

    let allowed = SignRequest::StarkRawMessage {
        secret: SecretRef::new("stark-secret").unwrap(),
        key_domain: StarkKeyDomain::StarknetAccount,
        derivation_path: DerivationPath {
            coin_type: 9004,
            account_index: 0,
            address_index: 1,
        },
        message: FeltHex::parse("0x1234").unwrap(),
        allow_raw_stark_hash: true,
    };
    assert!(allowed.validate().is_ok());
}

#[test]
fn raw_nostr_sign_request_accepts_utf8_or_hex_bytes() {
    let utf8_request = SignRequest::NostrRawMessage {
        secret: SecretRef::new("nostr-secret").unwrap(),
        derivation_path: DerivationPath {
            coin_type: 1237,
            account_index: 0,
            address_index: 7,
        },
        payload: RawMessagePayload::Utf8("hello nostr".to_string()),
    };
    assert!(utf8_request.validate().is_ok());

    let hex_request = SignRequest::NostrRawMessage {
        secret: SecretRef::new("nostr-secret").unwrap(),
        derivation_path: DerivationPath {
            coin_type: 1237,
            account_index: 0,
            address_index: 7,
        },
        payload: RawMessagePayload::Hex(HexBytes::parse("68656c6c6f").unwrap()),
    };
    assert!(hex_request.validate().is_ok());
}

#[test]
fn operation_status_serializes_machine_shape() {
    let status = OperationStatus {
        id: OperationId::new("deploy-1").unwrap(),
        kind: OperationKind::DeployAccount,
        state: OperationState::Submitted {
            tx_hash: FeltHex::parse("0x123").unwrap(),
        },
        provenance: Some(Provenance {
            chain_id: ChainId::Sepolia,
            key_domain: KeyDomain::StarknetAccount,
            derivation_path: DerivationPath {
                coin_type: 9004,
                account_index: 0,
                address_index: 0,
            },
            class_hash: Some(FeltHex::parse("0x456").unwrap()),
        }),
    };

    let json = serde_json::to_string(&status).unwrap();
    let roundtrip: OperationStatus = serde_json::from_str(&json).unwrap();

    assert_eq!(roundtrip, status);
    assert!(json.contains("\"Submitted\""));
    assert!(json.contains("\"DeployAccount\""));
}

#[test]
fn account_snapshot_request_serializes_canonical_addresses() {
    let request = AccountSnapshotRequest {
        chain_id: ChainId::Sepolia,
        address: FeltHex::parse("0xabc").unwrap(),
        tokens: vec![TrackedToken {
            symbol: "STRK".into(),
            address: FeltHex::parse(
                "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
            )
            .unwrap(),
            decimals: 18,
        }],
        block: BlockSelector::Latest,
        mode: QueryMode::ActiveView,
        cache_policy: CachePolicy::new(2_500, 500, 32).unwrap(),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("0x0000000000000000000000000000000000000000000000000000000000000abc"));
}
