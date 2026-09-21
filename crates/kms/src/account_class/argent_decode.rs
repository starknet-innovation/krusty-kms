//! Reading Argent constructor calldata back from a deployment.
//!
//! [`ArgentConstructorLayout::constructor_calldata`] builds the guardian-less
//! calldata a seed can reproduce; [`ArgentConstructorLayout::decode`] is its
//! converse for calldata read from a real `DEPLOY_ACCOUNT`, recovering what
//! derivability and verification depend on: the owner kind, the owner key and
//! the guardian, if one is set.

use super::ArgentConstructorLayout;
use krusty_kms_common::{KmsError, Result};
use starknet_types_core::felt::Felt;

/// Constructor arguments recovered from on-chain calldata. See
/// [`ArgentConstructorLayout::decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedArgentConstructor {
    /// A Starknet-key owner and no guardian: the address depends on the owner
    /// key alone, so a seed reproduces it without knowing the address.
    StarknetOwnerNoGuardian { owner: Felt },
    /// A Starknet-key owner and a guardian. The guardian is per-account and
    /// not derived from the seed, so discovery cannot enumerate this address;
    /// once the address is known,
    /// [`ArgentConstructorLayout::constructor_calldata_with_guardian`]
    /// reproduces it. `guardian` is the guardian's Stark key when it is a
    /// Starknet signer and `None` for the other signer types.
    StarknetOwnerWithGuardian { owner: Felt, guardian: Option<Felt> },
    /// The owner is not a Starknet signer. `variant` is the v0.4.0+ `Signer`
    /// variant index (1 Secp256k1, 2 Secp256r1, 3 EIP-191, 4 WebAuthn). The
    /// guardian is not decoded: non-Starknet payloads vary in length.
    NonStarknetOwner { variant: u8 },
}

impl ArgentConstructorLayout {
    /// Read deployed constructor calldata back as this layout deserialises it.
    ///
    /// Recovers the owner kind, the owner key and the guardian: the inputs
    /// that decide whether the address is a function of a seed and, if not,
    /// what reproduces it. Returns [`KmsError::DeserializationError`] for
    /// calldata this layout cannot have accepted.
    pub fn decode(self, calldata: &[Felt]) -> Result<DecodedArgentConstructor> {
        match self {
            Self::OwnerGuardianFelts => decode_owner_guardian_felts(calldata),
            Self::SignerWithOptionalGuardian => decode_signer_with_optional_guardian(calldata),
        }
    }
}

fn malformed(detail: &str) -> KmsError {
    KmsError::DeserializationError(format!("Argent constructor calldata: {detail}"))
}

fn decode_owner_guardian_felts(calldata: &[Felt]) -> Result<DecodedArgentConstructor> {
    let [owner, guardian] = calldata else {
        return Err(malformed(&format!(
            "expected [owner, guardian], got {} felts",
            calldata.len()
        )));
    };
    if *owner == Felt::ZERO {
        return Err(malformed("owner is zero"));
    }
    Ok(if *guardian == Felt::ZERO {
        DecodedArgentConstructor::StarknetOwnerNoGuardian { owner: *owner }
    } else {
        DecodedArgentConstructor::StarknetOwnerWithGuardian {
            owner: *owner,
            guardian: Some(*guardian),
        }
    })
}

fn decode_signer_with_optional_guardian(calldata: &[Felt]) -> Result<DecodedArgentConstructor> {
    let Some((owner_variant, rest)) = calldata.split_first() else {
        return Err(malformed("empty"));
    };
    if *owner_variant != Felt::ZERO {
        // Non-Starknet owner payloads vary in length, so the guardian cannot
        // be located; the owner kind alone settles derivability.
        return match small_u8(owner_variant) {
            Some(variant @ 1..=4) => Ok(DecodedArgentConstructor::NonStarknetOwner { variant }),
            _ => Err(malformed("owner tag is not a Signer variant")),
        };
    }
    let decoded = match rest {
        // Signer::Starknet(owner), Option::None
        [owner, tag] if *tag == Felt::ONE => {
            DecodedArgentConstructor::StarknetOwnerNoGuardian { owner: *owner }
        }
        // Signer::Starknet(owner), Option::Some(Signer::Starknet(guardian))
        [owner, tag, variant, guardian] if *tag == Felt::ZERO && *variant == Felt::ZERO => {
            DecodedArgentConstructor::StarknetOwnerWithGuardian {
                owner: *owner,
                guardian: Some(*guardian),
            }
        }
        // Signer::Starknet(owner), Option::Some(<other signer>): the payload
        // length varies by signer type, so the guardian key is not recovered.
        [owner, tag, variant, _payload, ..]
            if *tag == Felt::ZERO && matches!(small_u8(variant), Some(1..=4)) =>
        {
            DecodedArgentConstructor::StarknetOwnerWithGuardian {
                owner: *owner,
                guardian: None,
            }
        }
        _ => {
            return Err(malformed(
                "expected [0, owner, 1] or [0, owner, 0, guardian...]",
            ))
        }
    };
    match decoded {
        DecodedArgentConstructor::StarknetOwnerNoGuardian { owner }
        | DecodedArgentConstructor::StarknetOwnerWithGuardian { owner, .. }
            if owner == Felt::ZERO =>
        {
            Err(malformed("owner is zero"))
        }
        other => Ok(other),
    }
}

/// The felt as a `u8`, if it fits.
fn small_u8(felt: &Felt) -> Option<u8> {
    let bytes = felt.to_bytes_be();
    bytes[..31].iter().all(|b| *b == 0).then_some(bytes[31])
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn test_decode_reports_foreign_signers() {
        let pk = Felt::from(42u64);
        // Signer::Secp256r1 owner: variant 2, u256 payload.
        assert_eq!(
            ArgentConstructorLayout::SignerWithOptionalGuardian
                .decode(&[Felt::TWO, Felt::ONE, Felt::ONE, Felt::ONE])
                .unwrap(),
            DecodedArgentConstructor::NonStarknetOwner { variant: 2 }
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

    #[test]
    fn test_decode_rejects_calldata_no_layout_accepts() {
        let pk = Felt::from(42u64);
        let cases: [(ArgentConstructorLayout, &[Felt]); 8] = [
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
}
