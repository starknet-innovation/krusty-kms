//! Unit tests for STRK20 viewing-key derivation.

use super::*;
use num_bigint::BigUint;
use num_traits::Num;

fn reference_order() -> BigUint {
    BigUint::from_str_radix(
        "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f",
        16,
    )
    .unwrap()
}

fn to_biguint(felt: &Felt) -> BigUint {
    BigUint::from_bytes_be(&felt.to_bytes_be())
}

fn vk_hex(private_key: &str) -> String {
    let pk = Felt::from_hex(private_key).expect("valid private key hex");
    format!("{:#x}", derive_strk20_viewing_key(&pk))
}

/// Domain keccak anchored to starknet.js `hash.starknetKeccak(DOMAIN)`.
#[test]
fn domain_keccak_matches_starknet_js() {
    assert_eq!(
        format!(
            "{:#x}",
            starknet_keccak(STRK20_VIEWING_KEY_DOMAIN.as_bytes())
        ),
        "0x2da93d6437c3a6366d206b66d62846f06a35c1751250d74d4fd1b2c68838d41",
    );
}

/// Known-answer vectors generated independently with `starknet@10.0.2`:
/// `Pedersen(starknetKeccak(DOMAIN), pk) % (CURVE.n / 2) + 1`.
#[test]
fn viewing_key_known_answers() {
    assert_eq!(
        vk_hex("0x1"),
        "0x18c6e892dbe125696102d8c69a3adc9ca0c73d92bcb35fa166c2cb92914ba05",
    );
    assert_eq!(
        vk_hex("0x2"),
        "0xb3914270984ae1ddc5bb5586f9558cf26666a63096fd18fbbaff342ffdba01",
    );
    assert_eq!(
        vk_hex("0xdeadbeef"),
        "0xb8055c8793acf944ec7d69de834ebd88db9f5a7e19f0ecbbc6c17cb0ffbb66",
    );
    assert_eq!(
        vk_hex("0x07a1f2c3b4a5968778695a4b3c2d1e0f00112233445566778899aabbccddeeff"),
        "0x206f4f73f030abbaf454d1a66376ce1fe63e6938df1669753b84f30777e6116",
    );
}

#[test]
fn viewing_key_is_deterministic_and_in_range() {
    let pk = Felt::from_hex("0xabc").unwrap();
    let a = derive_strk20_viewing_key(&pk);
    let b = derive_strk20_viewing_key(&pk);
    assert_eq!(a, b);

    let a = to_biguint(&a);
    assert!(a >= BigUint::from(1u8));
    assert!(a <= reference_order() >> 1);
}

fn scoped_hex(private_key: &str, chain_id: &str, pool_address: &str) -> String {
    let private_key = Felt::from_hex(private_key).unwrap();
    format!(
        "{:#x}",
        derive_scoped_strk20_viewing_key(&private_key, chain_id, pool_address).unwrap()
    )
}

#[test]
fn scoped_known_answers_match_the_privacy_demo() {
    assert_eq!(
        scoped_hex("0x1", "0x534e5f5345504f4c4941", "0x123"),
        "0x27cae3ff78010cbec0f29c0c94420cc4d41ca326d664e510cca4dcc6082beb3",
    );
    assert_eq!(
        scoped_hex("0x1", "0x534e5f4d41494e", "0x123"),
        "0x12e78a27fea179a0887b09dd9066d162240362c87756141473ecac377306338",
    );
    assert_eq!(
        scoped_hex("0xdeadbeef", "0x534e5f5345504f4c4941", "0x456"),
        "0x2d4dfb02335842c25e68b48e7b9c234aa40d17c90fe1d597bd47ccdc6388853",
    );
}

#[test]
fn scoped_derivation_is_the_verified_composition() {
    let private_key = Felt::from_hex("0xabc").unwrap();
    let message_hash = strk20_viewing_key_message_hash("0x1", "0x2").unwrap();
    let signature = sign_stark_hash(&private_key, &message_hash).unwrap();
    let staged = fold_strk20_viewing_key(
        &signature.public_key,
        &message_hash,
        &signature.r,
        &signature.s,
    )
    .unwrap();

    assert_eq!(
        derive_scoped_strk20_viewing_key(&private_key, "0x1", "0x2").unwrap(),
        staged,
    );
}

#[test]
fn fold_rejects_unverified_signature_material() {
    let private_key = Felt::from_hex("0xabc").unwrap();
    let message_hash = strk20_viewing_key_message_hash("0x1", "0x2").unwrap();
    let signature = sign_stark_hash(&private_key, &message_hash).unwrap();
    let other_public_key = crate::stark_signing::stark_public_key(&Felt::ONE).unwrap();

    assert!(
        fold_strk20_viewing_key(&other_public_key, &message_hash, &signature.r, &signature.s,)
            .is_err()
    );
    assert!(fold_strk20_viewing_key(
        &signature.public_key,
        &(message_hash + Felt::ONE),
        &signature.r,
        &signature.s,
    )
    .is_err());
    assert!(fold_strk20_viewing_key(
        &signature.public_key,
        &message_hash,
        &signature.s,
        &signature.r,
    )
    .is_err());
    assert!(fold_strk20_viewing_key(
        &signature.public_key,
        &message_hash,
        &Felt::ZERO,
        &signature.s,
    )
    .is_err());
}

fn fold(reduced: &BigUint) -> BigUint {
    let bytes = reduced.to_bytes_be();
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    let folded = fold_lower_half(&U256::from_be_slice(&padded));
    BigUint::from_bytes_be(&<[u8; 32]>::from(folded.to_be_bytes()))
}

#[test]
fn fold_is_strictly_below_half_order() {
    let order = reference_order();
    let half_order: BigUint = &order >> 1;
    let one = BigUint::from(1u8);

    assert_eq!(fold(&BigUint::from(0u8)), one);
    assert_eq!(fold(&one), one);
    assert_eq!(fold(&half_order), one);
    assert_eq!(fold(&(&half_order + &one)), one);
    assert_eq!(fold(&(&half_order - &one)), &half_order - &one);
    assert_eq!(
        fold(&(&half_order + BigUint::from(2u8))),
        &half_order - &one
    );
    assert_eq!(fold(&(&order - &one)), one);
    assert_eq!(fold(&(&order - BigUint::from(2u8))), BigUint::from(2u8));
}

/// The fixed-size arithmetic must give the same keys as the `num-bigint`
/// code it replaced, which is kept here as the reference.
#[test]
fn fixed_size_arithmetic_matches_the_big_integer_reference() {
    let order = reference_order();
    let half_order: BigUint = &order >> 1;
    let reference_fold = |reduced: BigUint| {
        let folded = if reduced < half_order {
            reduced
        } else {
            &order - reduced
        };
        if folded == BigUint::from(0u8) || folded >= half_order {
            BigUint::from(1u8)
        } else {
            folded
        }
    };

    let mut private_key = Felt::from_hex("0x5eed").unwrap();
    for _ in 0..256 {
        private_key = Pedersen::hash(&private_key, &Felt::ONE);

        let domain = starknet_keccak(STRK20_VIEWING_KEY_DOMAIN.as_bytes());
        let material = to_biguint(&Pedersen::hash(&domain, &private_key));
        assert_eq!(
            to_biguint(&derive_strk20_viewing_key(&private_key)),
            (material % &half_order) + BigUint::from(1u8),
        );

        assert_fold_matches(&private_key, &order, &reference_fold);
    }

    // The folded hash is any felt, so cover `[n, p)`, where reducing mod n
    // changes the value, and both ends of the field.
    let order_felt = Felt::from_bytes_be_slice(&order.to_bytes_be());
    for felt in [
        Felt::ZERO,
        Felt::ONE,
        order_felt - Felt::ONE,
        order_felt,
        order_felt + Felt::ONE,
        Felt::MAX,
    ] {
        assert_fold_matches(&felt, &order, &reference_fold);
    }
}

fn assert_fold_matches(
    material: &Felt,
    order: &BigUint,
    reference_fold: &dyn Fn(BigUint) -> BigUint,
) {
    let folded = fold_lower_half(&reduce_mod_order(material));
    assert_eq!(
        BigUint::from_bytes_be(&<[u8; 32]>::from(folded.to_be_bytes())),
        reference_fold(to_biguint(material) % order),
    );
}

#[test]
fn secret_fold_returns_the_same_key_as_the_plain_fold() {
    let private_key = Felt::from_hex("0xabc").unwrap();
    let hash = strk20_viewing_key_message_hash("0x1", "0x2").unwrap();
    let sig = sign_stark_hash(&private_key, &hash).unwrap();
    let secret = fold_strk20_secret_viewing_key(&sig.public_key, &hash, &sig.r, &sig.s).unwrap();
    let plain = fold_strk20_viewing_key(&sig.public_key, &hash, &sig.r, &sig.s).unwrap();
    assert_eq!(*secret.expose_secret(), plain);
    assert!(fold_strk20_secret_viewing_key(&sig.public_key, &hash, &sig.s, &sig.r).is_err());
}

#[test]
fn secret_variant_returns_the_same_scoped_key() {
    let private_key = Felt::from_hex("0xabc").unwrap();
    let secret = derive_scoped_strk20_secret_viewing_key(&private_key, "0x1", "0x2").unwrap();
    let plain = derive_scoped_strk20_viewing_key(&private_key, "0x1", "0x2").unwrap();
    assert_eq!(*secret.expose_secret(), plain);
}

#[test]
fn scoped_inputs_fail_closed() {
    let private_key = Felt::from_hex("0xabc").unwrap();
    assert!(strk20_viewing_key_message_hash("0x01", "0x2").is_err());
    assert!(strk20_viewing_key_message_hash("0x1", "0x0").is_err());
    assert!(strk20_viewing_key_message_hash("not-hex", "0x2").is_err());
    assert!(derive_scoped_strk20_viewing_key(&Felt::ZERO, "0x1", "0x2").is_err());
    assert!(derive_scoped_strk20_viewing_key(&private_key, "", "0x2").is_err());
}
