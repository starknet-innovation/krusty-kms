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

pub use audit::{AuditPrefixData, AuditProver};
pub use curve::StarkCurve;
pub use elgamal::{recover_small_discrete_log, ElGamal, ElGamalEncryption};
pub use hash::poseidon_hash_many;
pub use poe::ProofOfExponentiation;
pub use poe2::ProofOfExponentiation2;
#[cfg(feature = "test-utils")]
pub use random::{clear_deterministic_rng, set_deterministic_rng};
pub use random::{fill_random_bytes, random_felt, random_felts};
