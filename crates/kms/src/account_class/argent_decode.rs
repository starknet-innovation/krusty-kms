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
    /// calldata this layout cannot have accepted, including a payload of the
    /// right length whose values fall outside the types the constructor
    /// deserialises.
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
    let (owner_tag, rest) = calldata.split_first().ok_or_else(|| malformed("empty"))?;
    let (owner, after_owner) = split_signer(owner_tag, rest, "owner")?;
    let guardian = split_optional_signer(after_owner)?;

    let Signer::Starknet(owner_key) = owner else {
        // A non-Starknet owner settles derivability on its own; the guardian
        // is validated above but its key is not reported.
        return Ok(DecodedArgentConstructor::NonStarknetOwner {
            variant: owner.variant(),
        });
    };
    Ok(match guardian {
        None => DecodedArgentConstructor::StarknetOwnerNoGuardian { owner: owner_key },
        Some(Signer::Starknet(key)) => DecodedArgentConstructor::StarknetOwnerWithGuardian {
            owner: owner_key,
            guardian: Some(key),
        },
        Some(_) => DecodedArgentConstructor::StarknetOwnerWithGuardian {
            owner: owner_key,
            guardian: None,
        },
    })
}

/// A `Signer` as far as this decoder reads it: the Starknet variant carries
/// its key, the others only their variant index.
enum Signer {
    Starknet(Felt),
    Other(u8),
}

impl Signer {
    fn variant(&self) -> u8 {
        match self {
            Self::Starknet(_) => 0,
            Self::Other(variant) => *variant,
        }
    }
}

/// Split one serialised `Signer` (variant tag already taken) off the front of
/// `payload`, returning it and the felts that follow.
///
/// Widths and value ranges are those of Argent's `Signer` variants, so
/// calldata the constructor could not deserialise is rejected rather than
/// classified: `StarknetSigner` one non-zero felt; `Secp256k1Signer` and
/// `Eip191Signer` one non-zero `EthAddress` each, which is 160 bits;
/// `Secp256r1Signer` a non-zero `u256`, whose two limbs are `u128`s; and
/// `WebauthnSigner` a length-prefixed `origin` of `u8`s followed by two
/// non-zero `u256`s.
fn split_signer<'a>(tag: &Felt, payload: &'a [Felt], what: &str) -> Result<(Signer, &'a [Felt])> {
    let variant = small_usize(tag)
        .and_then(|variant| u8::try_from(variant).ok())
        .ok_or_else(|| malformed(&format!("{what} tag is not a Signer variant")))?;
    let width = match variant {
        0 | 1 | 3 => 1,
        2 => 2,
        4 => {
            let origin_len = payload
                .first()
                .and_then(small_usize)
                .ok_or_else(|| malformed(&format!("{what} webauthn origin length")))?;
            origin_len
                .checked_add(5)
                .ok_or_else(|| malformed(&format!("{what} webauthn origin length")))?
        }
        _ => return Err(malformed(&format!("{what} tag is not a Signer variant"))),
    };
    if payload.len() < width {
        return Err(malformed(&format!("{what} payload is truncated")));
    }
    let (payload, rest) = payload.split_at(width);

    let valid = match variant {
        // NonZero<felt252>.
        0 => payload[0] != Felt::ZERO,
        // EthAddress, asserted non-zero by the constructor.
        1 | 3 => payload[0] != Felt::ZERO && fits(&payload[0], ETH_ADDRESS_BYTES),
        // NonZero<u256>.
        2 => is_nonzero_u256(payload),
        4 => is_valid_webauthn(payload),
        _ => unreachable!("width matched the same variants"),
    };
    if !valid {
        return Err(malformed(&format!("{what} payload is out of range")));
    }

    let signer = if variant == 0 {
        Signer::Starknet(payload[0])
    } else {
        Signer::Other(variant)
    };
    Ok((signer, rest))
}

/// Read the trailing `Option<Signer>` guardian, which must consume the rest of
/// the calldata exactly.
fn split_optional_signer(calldata: &[Felt]) -> Result<Option<Signer>> {
    let (tag, rest) = calldata
        .split_first()
        .ok_or_else(|| malformed("guardian option is missing"))?;
    let (guardian, rest) = if *tag == Felt::ONE {
        (None, rest)
    } else if *tag == Felt::ZERO {
        let (tag, payload) = rest
            .split_first()
            .ok_or_else(|| malformed("guardian signer is missing"))?;
        let (signer, rest) = split_signer(tag, payload, "guardian")?;
        (Some(signer), rest)
    } else {
        return Err(malformed("guardian option tag is not 0 or 1"));
    };
    if !rest.is_empty() {
        return Err(malformed("trailing felts after the guardian"));
    }
    Ok(guardian)
}

/// Bytes of an `EthAddress`, which Cairo accepts only below 2^160.
const ETH_ADDRESS_BYTES: usize = 20;
/// Bytes of a `u256` limb.
const U128_BYTES: usize = 16;

/// Whether the felt fits in `bytes` bytes. Every width Argent's signers use is
/// byte-aligned.
fn fits(felt: &Felt, bytes: usize) -> bool {
    felt.to_bytes_be()[..32 - bytes]
        .iter()
        .all(|byte| *byte == 0)
}

/// A `u256` is `[low, high]`, each a `u128`; Argent's uses are `NonZero`.
fn is_nonzero_u256(limbs: &[Felt]) -> bool {
    limbs.len() == 2
        && limbs.iter().all(|limb| fits(limb, U128_BYTES))
        && limbs.iter().any(|limb| *limb != Felt::ZERO)
}

/// `WebauthnSigner`: a length-prefixed `origin` of `u8`s, then `rp_id_hash`
/// and `pubkey`, both non-zero `u256`s.
fn is_valid_webauthn(payload: &[Felt]) -> bool {
    let Some((origin_len, rest)) = payload.split_first() else {
        return false;
    };
    let Some(origin_len) = small_usize(origin_len) else {
        return false;
    };
    if rest.len() != origin_len + 4 {
        return false;
    }
    let (origin, keys) = rest.split_at(origin_len);
    origin.iter().all(|byte| fits(byte, 1))
        && is_nonzero_u256(&keys[..2])
        && is_nonzero_u256(&keys[2..])
}

/// The felt as a `usize`, if it fits.
fn small_usize(felt: &Felt) -> Option<usize> {
    let bytes = felt.to_bytes_be();
    if bytes[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&bytes[24..]);
    usize::try_from(u64::from_be_bytes(tail)).ok()
}

#[cfg(test)]
mod tests;
