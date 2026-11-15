use super::serialize_ae_balance;
use starknet_types_core::felt::Felt;

#[test]
fn serialize_ae_balance_validates_sizes() {
    assert!(serialize_ae_balance(&[0u8; 63], &[0u8; 24]).is_err());
    assert!(serialize_ae_balance(&[0u8; 64], &[0u8; 23]).is_err());
}

#[test]
fn serialize_ae_balance_uses_cairo_integer_limb_order() {
    let ciphertext: [u8; 64] = std::array::from_fn(|i| i as u8);
    let nonce: [u8; 24] = std::array::from_fn(|i| (0x80 + i) as u8);
    let limbs = serialize_ae_balance(&ciphertext, &nonce).unwrap();
    for i in 0..4 {
        let source = &ciphertext[(3 - i) * 16..(4 - i) * 16];
        let mut chunk = [0u8; 16];
        chunk.copy_from_slice(source);
        assert_eq!(limbs[i], Felt::from(u128::from_be_bytes(chunk)));
    }
    let mut low = [0u8; 16];
    low.copy_from_slice(&nonce[8..24]);
    let mut high = [0u8; 8];
    high.copy_from_slice(&nonce[..8]);
    assert_eq!(limbs[4], Felt::from(u128::from_be_bytes(low)));
    assert_eq!(limbs[5], Felt::from(u64::from_be_bytes(high)));
}
