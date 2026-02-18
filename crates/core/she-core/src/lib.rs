//! Somewhat Homomorphic Encryption (SHE) for Starknet.
//!
//! This crate implements the core cryptographic primitives for the TONGO protocol:
//! - Elliptic curve operations on the Stark curve
//! - Proof of Exponentiation (PoE) protocols
//! - ElGamal encryption with zero-knowledge proofs
//! - Range proofs for proving values are in [0, 2^n - 1]
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

pub mod audit;
pub mod bit;
pub mod curve;
pub mod elgamal;
pub mod hash;
pub mod poe;
pub mod poe2;
pub mod random;
pub mod range;
pub mod scalar;

pub use audit::AuditProver;
pub use curve::StarkCurve;
pub use elgamal::{ElGamal, ElGamalEncryption};
pub use hash::poseidon_hash_many;
pub use poe::ProofOfExponentiation;
pub use poe2::ProofOfExponentiation2;
pub use random::{
    clear_deterministic_rng, fill_random_bytes, random_felt, random_felts, set_deterministic_rng,
};

/// Re-export common types
pub use ghoul_common::*;
