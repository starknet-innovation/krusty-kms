//! Computer Quarterback - A Lying Prover Game
//!
//! A football-themed game demonstrating cryptographic commitment schemes and
//! probabilistic verification. Players can lie about play outcomes and try
//! to get away with it - bigger lies mean bigger potential gains but higher
//! detection probability.
//!
//! # Core Mechanics
//!
//! 1. Both offense and defense commit to plays (cryptographic binding)
//! 2. Plays are revealed simultaneously
//! 3. True outcome calculated from payoff matrix
//! 4. Offense can claim MORE yards than true outcome
//! 5. Probabilistic verification: P(caught) = 1 - e^(-0.15 * lie_magnitude)
//! 6. If caught: penalty; if not caught: claimed yards count

pub mod commitment;
pub mod detection;
pub mod payoff;
pub mod types;
pub mod verification;

// Re-exports
pub use commitment::*;
pub use detection::*;
pub use payoff::*;
pub use types::*;
pub use verification::*;
