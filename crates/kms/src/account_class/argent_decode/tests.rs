//! Tests for the argent decode module.

use super::*;

const LAYOUTS: [ArgentConstructorLayout; 2] = [
    ArgentConstructorLayout::OwnerGuardianFelts,
    ArgentConstructorLayout::SignerWithOptionalGuardian,
];

#[test]
fn test_decode_round_trips_the_guardian_less_calldata() {
    let pk = Felt::from(42u64);
    for layout in LAYOUTS {
        assert_eq!(
            layout.decode(&layout.constructor_calldata(&pk)).unwrap(),
            DecodedArgentConstructor::StarknetOwnerNoGuardian { owner: pk }
        );
    }
}

#[test]
fn test_decode_round_trips_the_guardian_calldata() {
    let pk = Felt::from(42u64);
    let guardian = Felt::from(7u64);
    for layout in LAYOUTS {
        let calldata = layout.constructor_calldata_with_guardian(&pk, &guardian);
        assert_eq!(
            layout.decode(&calldata).unwrap(),
            DecodedArgentConstructor::StarknetOwnerWithGuardian {
                owner: pk,
                guardian: Some(guardian),
            },
            "{layout:?}"
        );
    }
    // The v0.4.0+ shape observed on Mainnet: (0, pk, 0, 0, guardian).
    assert_eq!(
        ArgentConstructorLayout::SignerWithOptionalGuardian
            .constructor_calldata_with_guardian(&pk, &guardian),
        vec![Felt::ZERO, pk, Felt::ZERO, Felt::ZERO, guardian]
    );
}

/// A zero guardian is "no guardian" on every layout. On v0.4.0+ a literal
/// `[0, pk, 0, 0, 0]` is undeployable (`NonZero` guardian key), so the
/// builder must never emit it.
#[test]
fn test_zero_guardian_is_the_guardian_less_calldata() {
    let pk = Felt::from(42u64);
    for layout in LAYOUTS {
        let calldata = layout.constructor_calldata_with_guardian(&pk, &Felt::ZERO);
        assert_eq!(calldata, layout.constructor_calldata(&pk), "{layout:?}");
        assert_eq!(
            layout.decode(&calldata).unwrap(),
            DecodedArgentConstructor::StarknetOwnerNoGuardian { owner: pk }
        );
    }
}

#[test]
fn test_decode_reports_foreign_signers() {
    let pk = Felt::from(42u64);
    // Signer::Secp256r1 owner (variant 2, u256), no guardian.
    assert_eq!(
        ArgentConstructorLayout::SignerWithOptionalGuardian
            .decode(&[Felt::TWO, Felt::ONE, Felt::ONE, Felt::ONE])
            .unwrap(),
        DecodedArgentConstructor::NonStarknetOwner { variant: 2 }
    );
    // Signer::Webauthn owner (variant 4): origin is length-prefixed.
    let webauthn = [
        Felt::from(4u64),
        Felt::TWO, // origin length
        Felt::from(b'h'),
        Felt::from(b'i'),
        Felt::ONE,  // rp_id_hash low
        Felt::ZERO, // rp_id_hash high
        Felt::ONE,  // pubkey low
        Felt::ZERO, // pubkey high
        Felt::ONE,  // Option::None guardian
    ];
    assert_eq!(
        ArgentConstructorLayout::SignerWithOptionalGuardian
            .decode(&webauthn)
            .unwrap(),
        DecodedArgentConstructor::NonStarknetOwner { variant: 4 }
    );
    // Starknet owner, Secp256r1 guardian: the guardian key is not a felt.
    assert_eq!(
        ArgentConstructorLayout::SignerWithOptionalGuardian
            .decode(&[Felt::ZERO, pk, Felt::ZERO, Felt::TWO, Felt::ONE, Felt::ONE])
            .unwrap(),
        DecodedArgentConstructor::StarknetOwnerWithGuardian {
            owner: pk,
            guardian: None,
        }
    );
}

/// `decode` rejects calldata the constructor could not deserialise, so a
/// truncated or over-long payload is an error, not a verdict.
#[test]
fn test_decode_rejects_incomplete_signer_payloads() {
    let pk = Felt::from(42u64);
    let cases: [(&str, &[Felt]); 6] = [
        // A variant tag with no payload and no guardian option.
        ("bare non-Starknet tag", &[Felt::ONE]),
        // Secp256r1 owner missing the second half of its u256.
        ("truncated u256", &[Felt::TWO, Felt::ONE, Felt::ONE]),
        // Webauthn owner whose origin length exceeds the calldata.
        (
            "truncated webauthn",
            &[Felt::from(4u64), Felt::from(9u64), Felt::ONE],
        ),
        // Starknet owner, no guardian option at all.
        ("missing guardian option", &[Felt::ZERO, pk]),
        // Guardian option tag that is neither Some nor None.
        ("bad option tag", &[Felt::ZERO, pk, Felt::TWO]),
        // Well-formed, then junk.
        ("trailing felts", &[Felt::ZERO, pk, Felt::ONE, Felt::ONE]),
    ];
    for (name, calldata) in cases {
        match ArgentConstructorLayout::SignerWithOptionalGuardian.decode(calldata) {
            Err(KmsError::DeserializationError(msg)) => {
                assert!(msg.contains("Argent constructor calldata"), "{name}: {msg}")
            }
            other => panic!("{name}: expected rejection, got {other:?}"),
        }
    }
}

#[test]
fn test_decode_rejects_calldata_no_layout_accepts() {
    let pk = Felt::from(42u64);
    let cases: [(ArgentConstructorLayout, &[Felt]); 9] = [
        (ArgentConstructorLayout::OwnerGuardianFelts, &[pk]),
        (
            ArgentConstructorLayout::OwnerGuardianFelts,
            &[Felt::ZERO, Felt::ZERO],
        ),
        (ArgentConstructorLayout::SignerWithOptionalGuardian, &[]),
        // The historical `[0, pk, 0]`: a Some tag with no payload.
        (
            ArgentConstructorLayout::SignerWithOptionalGuardian,
            &[Felt::ZERO, pk, Felt::ZERO],
        ),
        (
            ArgentConstructorLayout::SignerWithOptionalGuardian,
            &[Felt::ZERO, Felt::ZERO, Felt::ONE],
        ),
        // Variant 9 is not a Signer, as owner or as guardian.
        (
            ArgentConstructorLayout::SignerWithOptionalGuardian,
            &[Felt::from(9u64), pk, Felt::ONE],
        ),
        (
            ArgentConstructorLayout::SignerWithOptionalGuardian,
            &[Felt::ZERO, pk, Felt::ZERO, Felt::from(9u64), Felt::ONE],
        ),
        // A Starknet guardian with no key.
        (
            ArgentConstructorLayout::SignerWithOptionalGuardian,
            &[Felt::ZERO, pk, Felt::ZERO, Felt::ZERO],
        ),
        // A Starknet guardian whose key is zero: `NonZero` rejects it.
        (
            ArgentConstructorLayout::SignerWithOptionalGuardian,
            &[Felt::ZERO, pk, Felt::ZERO, Felt::ZERO, Felt::ZERO],
        ),
    ];
    for (layout, calldata) in cases {
        match layout.decode(calldata) {
            Err(KmsError::DeserializationError(msg)) => {
                assert!(msg.contains("Argent constructor calldata"), "{msg}")
            }
            other => panic!("{layout:?} {calldata:?}: expected rejection, got {other:?}"),
        }
    }
}
