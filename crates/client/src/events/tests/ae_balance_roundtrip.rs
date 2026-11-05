use super::super::{parse_ae_balance, StarknetRsFelt};
use krusty_kms_common::serialize_ae_balance;

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
