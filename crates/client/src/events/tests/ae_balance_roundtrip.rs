use super::super::{parse_ae_balance, parse_transfer_event, tongo_events, StarknetRsFelt};
use crate::types::AEBalanceLayout;
use krusty_kms_common::{
    serialize_ae_balance, AuditProof, ElGamalCiphertext, PoeProof, SerializablePoint,
};
use krusty_kms_sdk::operations::{Audit, FundProof};
use starknet_rust_core::types::EmittedEvent;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

#[test]
fn serialized_ae_balance_round_trips_through_event_parser() {
    let cases = [
        (
            std::array::from_fn(|i| i as u8),
            std::array::from_fn(|i| 0xa0 + i as u8),
        ),
        ([0xff; 64], [0xff; 24]),
        ([0; 64], [0; 24]),
    ];

    for (ciphertext, nonce) in cases {
        let encoded = serialize_ae_balance(&ciphertext, &nonce).unwrap();
        let event_data: Vec<_> = std::iter::once(StarknetRsFelt::ZERO)
            .chain(
                encoded
                    .into_iter()
                    .map(|felt| StarknetRsFelt::from_bytes_be(&felt.to_bytes_be())),
            )
            .collect();

        let decoded = parse_ae_balance(&event_data, 1).unwrap();
        assert_eq!(decoded.ciphertext, ciphertext);
        assert_eq!(decoded.nonce, nonce);
    }
}

#[test]
fn event_parser_rejects_noncanonical_ae_hint_limbs() {
    let exceeds_u128 = StarknetRsFelt::from_hex("0x100000000000000000000000000000000").unwrap();
    for index in [0, 4, 5] {
        let mut data = [StarknetRsFelt::ZERO; 6];
        data[index] = exceeds_u128;
        assert!(parse_ae_balance(&data, 0).is_err());
    }
}

#[test]
fn legacy_ae_hint_layout_remains_readable() {
    let ciphertext: [u8; 64] = std::array::from_fn(|i| i as u8);
    let nonce: [u8; 24] = std::array::from_fn(|i| 0x80 + i as u8);
    let mut zero_prefix_nonce = nonce;
    zero_prefix_nonce[..8].fill(0);
    for nonce in [nonce, zero_prefix_nonce] {
        let data = legacy_ae_hint_felts(ciphertext, nonce);
        let decoded = parse_ae_balance(&data, 0).unwrap();
        assert_eq!(decoded.ciphertext, ciphertext);
        assert_eq!(decoded.nonce, nonce);
        let [guess, alternate] = decoded.candidates();
        assert_eq!(guess.layout, AEBalanceLayout::Legacy);
        assert_eq!(guess.ciphertext, ciphertext);
        assert_eq!(guess.nonce, nonce);
        assert_eq!(alternate.layout, AEBalanceLayout::Current);
    }
}

#[test]
fn colliding_current_nonce_keeps_both_layout_candidates() {
    let ciphertext: [u8; 64] = std::array::from_fn(|i| i as u8);
    let mut nonce: [u8; 24] = std::array::from_fn(|i| 0x80 + i as u8);
    nonce[16..].fill(0);
    let encoded = serialize_ae_balance(&ciphertext, &nonce).unwrap();
    let felts: Vec<_> = encoded
        .into_iter()
        .map(|felt| StarknetRsFelt::from_bytes_be(&felt.to_bytes_be()))
        .collect();
    let decoded = parse_ae_balance(&felts, 0).unwrap();
    let [guess, alternate] = decoded.candidates();
    assert_eq!(guess.layout, AEBalanceLayout::Legacy);
    assert_ne!(guess.ciphertext, ciphertext);
    assert_eq!(alternate.layout, AEBalanceLayout::Current);
    assert_eq!(alternate.ciphertext, ciphertext);
    assert_eq!(alternate.nonce, nonce);
}

#[test]
#[allow(deprecated)] // Exercise the still-public legacy auditor format.
fn legacy_ciphertext_can_use_current_cairo_limb_layout() {
    let user_private_key = Felt::from(42u64);
    let auditor_private_key = Felt::from(123u64);
    let user_public_key = krusty_kms_crypto::StarkCurve::mul_generator(&user_private_key);
    let auditor_public_key = krusty_kms_crypto::StarkCurve::mul_generator(&auditor_private_key);
    let (ciphertext, nonce) =
        krusty_kms_sdk::crypto::encrypt_for_auditor(77, &user_private_key, &auditor_public_key)
            .unwrap();
    let felts: Vec<_> = serialize_ae_balance(&ciphertext, &nonce)
        .unwrap()
        .into_iter()
        .map(|felt| StarknetRsFelt::from_bytes_be(&felt.to_bytes_be()))
        .collect();
    let decoded = parse_ae_balance(&felts, 0).unwrap();
    let current = decoded
        .candidates()
        .into_iter()
        .find(|candidate| candidate.layout == AEBalanceLayout::Current)
        .unwrap();
    assert_eq!(current.ciphertext, ciphertext);
    assert_eq!(current.nonce, nonce);

    assert!(krusty_kms_sdk::decrypt_as_auditor_with_context(
        &current.ciphertext,
        &current.nonce,
        &auditor_private_key,
        &user_public_key,
        &Felt::from(7u64),
        &Felt::from(9u64),
    )
    .is_err());
    assert_eq!(
        krusty_kms_sdk::crypto::decrypt_as_auditor(
            &current.ciphertext,
            &current.nonce,
            &auditor_private_key,
            &user_public_key,
        )
        .unwrap(),
        77
    );
}

#[test]
fn high_sender_hint_nonce_limb_does_not_reject_event() {
    let mut data = legacy_ae_hint_felts([0x46; 64], [0x9c; 24]);
    // A Cairo u256 limb may exceed u64. Previously this rejected the whole
    // event batch even though the old Krusty wire format used a u128 limb.
    data[5] = StarknetRsFelt::from_hex("0x10000000000000000").unwrap();
    data[4] = StarknetRsFelt::from(1u8);
    let decoded = parse_ae_balance(&data, 0).unwrap();
    let [guess, alternate] = decoded.candidates();
    assert_eq!(guess.layout, AEBalanceLayout::Legacy);
    assert_eq!(alternate.layout, AEBalanceLayout::Current);
    assert_eq!(alternate.nonce[16..], [0, 0, 0, 0, 0, 0, 0, 1]);
}

#[test]
fn sender_hint_with_u128_nonce_limb_keeps_transfer_batch_readable() {
    let generator = krusty_kms_crypto::StarkCurve::generator();
    let point = generator.to_affine().unwrap();
    let gx = StarknetRsFelt::from_bytes_be(&point.x().to_bytes_be());
    let gy = StarknetRsFelt::from_bytes_be(&point.y().to_bytes_be());
    let mut data = vec![StarknetRsFelt::ONE, gx, gy, gx, gy, gx, gy, gx, gy];
    let mut sender_hint = legacy_ae_hint_felts([0x46; 64], [0x9c; 24]);
    sender_hint[5] = StarknetRsFelt::from_hex("0x10000000000000000").unwrap();
    sender_hint[4] = StarknetRsFelt::ONE;
    data.extend(sender_hint);
    data.extend(legacy_ae_hint_felts([0x47; 64], [0x9d; 24]));
    let event = EmittedEvent {
        from_address: StarknetRsFelt::ONE,
        keys: vec![*tongo_events::TRANSFER_EVENT, gx, gy, gx, gy],
        data,
        block_hash: None,
        block_number: Some(1),
        transaction_hash: StarknetRsFelt::ONE,
        event_index: 0,
        transaction_index: 0,
    };
    let batch: Result<Vec<_>, _> = [event].iter().map(parse_transfer_event).collect();
    assert_eq!(batch.unwrap().len(), 1);
}

fn legacy_ae_hint_felts(ciphertext: [u8; 64], nonce: [u8; 24]) -> Vec<StarknetRsFelt> {
    let mut limbs = Vec::with_capacity(6);
    for chunk in ciphertext.as_chunks::<16>().0 {
        limbs.push(StarknetRsFelt::from(u128::from_be_bytes(*chunk)));
    }
    let mut nonce_low = [0u8; 16];
    nonce_low[..8].copy_from_slice(&nonce[16..]);
    let nonce_high: [u8; 16] = nonce[..16].try_into().unwrap();
    limbs.push(StarknetRsFelt::from(u128::from_be_bytes(nonce_low)));
    limbs.push(StarknetRsFelt::from(u128::from_be_bytes(nonce_high)));
    limbs
}

#[test]
fn fund_call_audit_hint_round_trips_through_event_parser() {
    let generator = krusty_kms_crypto::StarkCurve::generator();
    let affine = generator.to_affine().unwrap();
    let point = SerializablePoint::from_affine(&affine);
    let ciphertext: [u8; 64] = std::array::from_fn(|i| i as u8);
    let nonce: [u8; 24] = std::array::from_fn(|i| (0x80 + i) as u8);
    let proof = synthetic_fund_proof(generator, point, ciphertext, nonce);

    let (_, call) = crate::operations::build_fund_calls(
        Felt::from(1u8),
        Felt::from(2u8),
        1,
        &proof,
        &[0u8; 64],
        &[0u8; 24],
    )
    .unwrap();
    // Fund calldata has 12 felts before the audit option, then the Some tag
    // and four ElGamal ciphertext coordinates before its AE hint.
    assert_eq!(call.calldata[12], StarknetRsFelt::ZERO);
    let decoded = parse_ae_balance(&call.calldata, 17).unwrap();
    assert_eq!(decoded.ciphertext, ciphertext);
    assert_eq!(decoded.nonce, nonce);
}

fn synthetic_fund_proof(
    generator: ProjectivePoint,
    point: SerializablePoint,
    ciphertext: [u8; 64],
    nonce: [u8; 24],
) -> FundProof {
    let audit = Audit {
        audited_balance: ElGamalCiphertext {
            l: generator.clone(),
            r: generator.clone(),
        },
        hint_ciphertext: ciphertext,
        hint_nonce: nonce,
        proof: AuditProof {
            ax: point,
            al0: point,
            al1: point,
            ar1: point,
            sx: Felt::ZERO,
            sb: Felt::ZERO,
            sr: Felt::ZERO,
            c: Felt::ZERO,
        },
    };
    FundProof {
        y: generator,
        proof: PoeProof {
            a: point,
            s: Felt::ZERO,
            c: Felt::ZERO,
        },
        amount: 1,
        audit: Some(audit),
    }
}
