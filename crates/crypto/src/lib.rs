//! Cryptographic primitives and zero-knowledge proofs for krusty-kms.
//!
//! This crate owns the reusable math and proof systems used by higher layers:
//! - elliptic curve operations on the Stark curve
//! - Proof of Exponentiation (PoE) protocols
//! - ElGamal encryption with zero-knowledge proofs
//! - range proofs for proving values are in `[0, 2^n - 1]`
//!
//! # Architecture
//!
//! The library is organized into modules following DRY principles:
//! - `curve`: Low-level elliptic curve operations
//! - `hash`: Fiat-Shamir challenge generation
//! - `poe`: Proof of Exponentiation protocol
//! - `poe2`: Two-variable Proof of Exponentiation
//! - `elgamal`: ElGamal encryption with proofs
//! - `bit`: Bit proof protocol (OR proof for bit ∈ {0,1})
//! - `range`: Range proof protocol using bit proofs
//! - `audit`: Audit proof protocol (SameEncryptUnknownRandom)
//! - `random`: Efficient random value generation
//! - `scalar`: Scalar arithmetic operations
//! - `ml_dsa`: ML-DSA-65 (FIPS 204) key expansion and Cairo payload packing
//!   (behind the off-by-default `ml-dsa` feature)

#![forbid(unsafe_code)]

pub mod audit;
pub mod bit;
pub mod curve;
pub mod elgamal;
pub mod hash;
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;
pub mod poe;
pub mod poe2;
pub mod random;
pub mod range;
pub mod scalar;

pub use audit::{AuditPrefixData, AuditProver};
pub use curve::StarkCurve;
pub use elgamal::{recover_small_discrete_log, ElGamal, ElGamalEncryption};
pub use hash::{extend_pedersen_prefix, extend_poseidon_prefix, poseidon_hash_many};
#[cfg(feature = "ml-dsa")]
pub use ml_dsa::{
    ml_dsa_estimation_signature, ml_dsa_key_commitment, ml_dsa_packed_key,
    ml_dsa_signature_payload, ml_dsa_verify, ML_DSA_KEY_FELTS, ML_DSA_PAYLOAD_FELTS,
    ML_DSA_PUBLIC_KEY_BYTES, ML_DSA_SIGNATURE_BYTES,
};
pub use poe::ProofOfExponentiation;
pub use poe2::ProofOfExponentiation2;
#[cfg(feature = "insecure-deterministic-rng")]
pub use random::{clear_deterministic_rng, set_deterministic_rng};
pub use random::{
    fill_random_bytes, random_bytes, random_felt, random_felts, try_fill_random_bytes,
    try_random_bytes,
};
