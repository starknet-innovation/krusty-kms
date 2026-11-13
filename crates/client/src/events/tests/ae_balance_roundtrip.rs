use super::super::{parse_ae_balance, StarknetRsFelt};
use krusty_kms_common::{
    serialize_ae_balance, AuditProof, ElGamalCiphertext, PoeProof, SerializablePoint,
};
use krusty_kms_sdk::operations::{Audit, FundProof};
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
    let exceeds_u64 = StarknetRsFelt::from_hex("0x10000000000000000").unwrap();
    for (index, value) in [(0, exceeds_u128), (4, exceeds_u128), (5, exceeds_u64)] {
        let mut data = [StarknetRsFelt::ZERO; 6];
        data[index] = value;
        assert!(parse_ae_balance(&data, 0).is_err());
    }
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
