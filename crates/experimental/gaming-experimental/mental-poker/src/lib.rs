//! Mental Poker Protocol Implementation
//!
//! This crate implements the Barnett-Smart mental poker protocol for secure card games
//! without a trusted dealer. The implementation is based on:
//! - "Mental Poker Revisited" by Barnett and Smart (2003)
//! - Shuffle verification inspired by Bayer and Groth (2012)
//!
//! # Overview
//!
//! Mental poker allows players to play card games over a network without requiring
//! a trusted third party to shuffle and deal the cards. The protocol ensures:
//! - **Privacy**: Players cannot see each other's cards until revealed
//! - **Fairness**: No player can manipulate the deck
//! - **Verifiability**: All operations can be verified with zero-knowledge proofs
//!
//! # Features
//!
//! - **Key Generation**: Secure key pairs with Schnorr proofs of ownership
//! - **Card Masking**: ElGamal encryption of cards with DL equality proofs
//! - **Remasking**: Re-encryption without changing the underlying card
//! - **Shuffle with Proofs**: Verifiable shuffle using `shuffle_and_remask_with_proof`
//! - **Reveal Tokens**: Threshold decryption with verified partial decryptions
//! - **Batch Verification**: Efficient verification of multiple proofs
//!
//! # Architecture
//!
//! The library is organized into modules:
//! - `error`: Error types for the protocol
//! - `types`: Core type definitions (cards, proofs, keys)
//! - `zkp`: Zero-knowledge proof implementations (Schnorr, Chaum-Pedersen)
//! - `protocol`: The main Barnett-Smart protocol implementation
//! - `deck`: Deck management and card operations
//!
//! # Example
//!
//! ```rust
//! use mental_poker::{MentalPokerProtocol, deck::{CardEncoding, MaskedDeck}};
//!
//! // Each player generates their keys and proves ownership
//! let (pk1, sk1) = MentalPokerProtocol::player_keygen();
//! let (pk2, sk2) = MentalPokerProtocol::player_keygen();
//!
//! let proof1 = MentalPokerProtocol::prove_key_ownership(&pk1, &sk1, b"player1").unwrap();
//! let proof2 = MentalPokerProtocol::prove_key_ownership(&pk2, &sk2, b"player2").unwrap();
//!
//! // Compute aggregate public key
//! let keys = vec![
//!     (pk1, proof1, b"player1".to_vec()),
//!     (pk2, proof2, b"player2".to_vec()),
//! ];
//! let aggregate_pk = MentalPokerProtocol::compute_aggregate_key(&keys).unwrap();
//!
//! // Create and shuffle deck
//! let encoding = CardEncoding::standard_deck();
//! let deck = MaskedDeck::standard(&encoding, &aggregate_pk).unwrap();
//! let shuffled = deck.shuffle(&aggregate_pk).unwrap();
//! assert_eq!(shuffled.len(), 52);
//! ```

pub mod blackjack;
pub mod crossy;
pub mod deck;
pub mod error;
pub mod parallel;
pub mod protocol;
pub mod shuffle;
pub mod types;
pub mod utils;
pub mod zkp;

pub use error::MentalPokerError;
pub use parallel::ParallelOps;
pub use protocol::MentalPokerProtocol;
pub use types::*;

/// Re-export common types from ghoul-common
pub use ghoul_common::Result;
