//! Crossy Road / Mission Uncrossable game support.
//!
//! This module provides utilities for creating binary card decks
//! (Survive/Hit) used in Crossy Road style games. It extends the
//! mental poker protocol with game-specific semantics while reusing
//! the core cryptographic primitives.
//!
//! # Card Mapping
//!
//! - Index 1 = Survive (safe lane)
//! - Index 2 = Hit (obstacle/game over)
//!
//! # Example
//!
//! ```rust
//! use mental_poker::crossy::{CrossyDeckConfig, CrossyCardType, create_crossy_card_indices};
//!
//! // Create an easy difficulty deck (20 survive, 5 hit)
//! let config = CrossyDeckConfig::easy();
//! assert_eq!(config.total_cards(), 25);
//!
//! // Get card indices for the deck
//! let indices = create_crossy_card_indices(&config);
//! assert_eq!(indices.len(), 25);
//! ```

use crate::error::{MentalPokerError, Result};
use crate::types::Card;

// ============================================================================
// Card Type
// ============================================================================

/// The two card types in Crossy Road.
///
/// Cards are mapped to indices:
/// - Survive = 1 (g^1)
/// - Hit = 2 (g^2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrossyCardType {
    /// Safe lane - player survives and advances
    Survive = 1,
    /// Obstacle - player is hit, game over
    Hit = 2,
}

impl CrossyCardType {
    /// Get the card index for this type.
    pub fn index(&self) -> u64 {
        *self as u64
    }

    /// Create a cryptographic card from this type.
    pub fn to_card(&self) -> Card {
        Card::from_index(self.index())
    }

    /// Get the display string for this card type.
    pub fn display(&self) -> &'static str {
        match self {
            CrossyCardType::Survive => "Survive",
            CrossyCardType::Hit => "Hit",
        }
    }

    /// Get the symbol for this card type.
    pub fn symbol(&self) -> &'static str {
        match self {
            CrossyCardType::Survive => "O",
            CrossyCardType::Hit => "X",
        }
    }
}

impl std::fmt::Display for CrossyCardType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

// ============================================================================
// Deck Configuration
// ============================================================================

/// Configuration for a Crossy Road deck.
///
/// Determines the number of Survive and Hit cards in the deck.
/// Different configurations represent different difficulty levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossyDeckConfig {
    /// Number of Survive cards (safe lanes)
    pub survive_count: u32,
    /// Number of Hit cards (obstacles)
    pub hit_count: u32,
}

impl CrossyDeckConfig {
    /// Create a new deck configuration with custom counts.
    pub fn new(survive_count: u32, hit_count: u32) -> Self {
        Self {
            survive_count,
            hit_count,
        }
    }

    /// Easy difficulty: 20 survive, 5 hit (~80% survival rate per lane).
    pub fn easy() -> Self {
        Self::new(20, 5)
    }

    /// Medium difficulty: 15 survive, 10 hit (~60% survival rate per lane).
    pub fn medium() -> Self {
        Self::new(15, 10)
    }

    /// Hard difficulty: 10 survive, 15 hit (~40% survival rate per lane).
    pub fn hard() -> Self {
        Self::new(10, 15)
    }

    /// Daredevil difficulty: 5 survive, 20 hit (~20% survival rate per lane).
    pub fn daredevil() -> Self {
        Self::new(5, 20)
    }

    /// Get the total number of cards in the deck.
    pub fn total_cards(&self) -> u32 {
        self.survive_count + self.hit_count
    }

    /// Get the survival probability per lane selection.
    pub fn survival_rate(&self) -> f64 {
        if self.total_cards() == 0 {
            return 0.0;
        }
        self.survive_count as f64 / self.total_cards() as f64
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.total_cards() == 0 {
            return Err(MentalPokerError::InvalidDeckConfig(
                "deck must have at least one card".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for CrossyDeckConfig {
    fn default() -> Self {
        Self::medium()
    }
}

// ============================================================================
// Card Index Functions
// ============================================================================

/// Create the card indices for a Crossy Road deck.
///
/// Returns a vector of card indices (1 for Survive, 2 for Hit)
/// in the order they should be added to the deck.
///
/// # Example
///
/// ```rust
/// use mental_poker::crossy::{CrossyDeckConfig, create_crossy_card_indices};
///
/// let config = CrossyDeckConfig::easy();
/// let indices = create_crossy_card_indices(&config);
/// assert_eq!(indices.len(), 25);
/// // 20 survive cards (index 1) + 5 hit cards (index 2)
/// assert_eq!(indices.iter().filter(|&&i| i == 1).count(), 20);
/// assert_eq!(indices.iter().filter(|&&i| i == 2).count(), 5);
/// ```
pub fn create_crossy_card_indices(config: &CrossyDeckConfig) -> Vec<u64> {
    let mut indices = Vec::with_capacity(config.total_cards() as usize);

    // Add survive cards (index 1)
    for _ in 0..config.survive_count {
        indices.push(CrossyCardType::Survive.index());
    }

    // Add hit cards (index 2)
    for _ in 0..config.hit_count {
        indices.push(CrossyCardType::Hit.index());
    }

    indices
}

/// Resolve a card index to its CrossyCardType.
///
/// # Arguments
///
/// * `card_index` - The card index (1 for Survive, 2 for Hit)
///
/// # Errors
///
/// Returns an error if the index is not 1 or 2.
///
/// # Example
///
/// ```rust
/// use mental_poker::crossy::{resolve_crossy_card_type, CrossyCardType};
///
/// assert_eq!(resolve_crossy_card_type(1).unwrap(), CrossyCardType::Survive);
/// assert_eq!(resolve_crossy_card_type(2).unwrap(), CrossyCardType::Hit);
/// assert!(resolve_crossy_card_type(0).is_err());
/// assert!(resolve_crossy_card_type(3).is_err());
/// ```
pub fn resolve_crossy_card_type(card_index: u64) -> Result<CrossyCardType> {
    match card_index {
        1 => Ok(CrossyCardType::Survive),
        2 => Ok(CrossyCardType::Hit),
        _ => Err(MentalPokerError::InvalidCardIndex(format!(
            "invalid crossy card index: {} (expected 1 or 2)",
            card_index
        ))),
    }
}

/// Create cryptographic Card objects for a Crossy deck.
///
/// Returns a vector of Card objects corresponding to the deck configuration.
/// These can be used with the standard MaskedDeck::new() function.
pub fn create_crossy_cards(config: &CrossyDeckConfig) -> Vec<Card> {
    create_crossy_card_indices(config)
        .into_iter()
        .map(Card::from_index)
        .collect()
}

// ============================================================================
// Game Utilities
// ============================================================================

/// Calculate which card index to reveal for a given row and lane.
///
/// In a 5-lane Crossy Road game, the deck is laid out as:
/// - Row 0: indices 0-4
/// - Row 1: indices 5-9
/// - Row N: indices N*5 to N*5+4
///
/// # Arguments
///
/// * `row` - The current row (0-indexed)
/// * `lane` - The selected lane (1-5)
/// * `lanes_per_row` - Number of lanes per row (typically 5)
///
/// # Example
///
/// ```rust
/// use mental_poker::crossy::get_card_index_for_lane;
///
/// // Row 0, Lane 1 -> index 0
/// assert_eq!(get_card_index_for_lane(0, 1, 5), 0);
/// // Row 0, Lane 5 -> index 4
/// assert_eq!(get_card_index_for_lane(0, 5, 5), 4);
/// // Row 1, Lane 3 -> index 7
/// assert_eq!(get_card_index_for_lane(1, 3, 5), 7);
/// ```
pub fn get_card_index_for_lane(row: u32, lane: u32, lanes_per_row: u32) -> usize {
    (row * lanes_per_row + (lane - 1)) as usize
}

/// Calculate the multiplier for a given number of completed rows.
///
/// # Arguments
///
/// * `rows_completed` - Number of rows successfully crossed
/// * `base_multiplier` - Starting multiplier (typically 1.0)
/// * `increment` - Multiplier increase per row (e.g., 0.2)
///
/// # Example
///
/// ```rust
/// use mental_poker::crossy::calculate_multiplier;
///
/// assert_eq!(calculate_multiplier(0, 1.0, 0.25), 1.0);
/// assert_eq!(calculate_multiplier(1, 1.0, 0.25), 1.25);
/// assert_eq!(calculate_multiplier(4, 1.0, 0.25), 2.0);
/// ```
pub fn calculate_multiplier(rows_completed: u32, base_multiplier: f64, increment: f64) -> f64 {
    base_multiplier + (rows_completed as f64 * increment)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MentalPokerProtocol;

    // ========================================================================
    // CrossyCardType Tests
    // ========================================================================

    #[test]
    fn test_crossy_card_type_survive_index() {
        assert_eq!(CrossyCardType::Survive.index(), 1);
    }

    #[test]
    fn test_crossy_card_type_hit_index() {
        assert_eq!(CrossyCardType::Hit.index(), 2);
    }

    #[test]
    fn test_crossy_card_type_display() {
        assert_eq!(CrossyCardType::Survive.display(), "Survive");
        assert_eq!(CrossyCardType::Hit.display(), "Hit");
    }

    #[test]
    fn test_crossy_card_type_symbol() {
        assert_eq!(CrossyCardType::Survive.symbol(), "O");
        assert_eq!(CrossyCardType::Hit.symbol(), "X");
    }

    #[test]
    fn test_crossy_card_type_to_card() {
        let survive_card = CrossyCardType::Survive.to_card();
        let hit_card = CrossyCardType::Hit.to_card();

        // Cards should be different
        assert_ne!(survive_card.point, hit_card.point);

        // Should match cards created directly from indices
        assert_eq!(survive_card.point, Card::from_index(1).point);
        assert_eq!(hit_card.point, Card::from_index(2).point);
    }

    // ========================================================================
    // CrossyDeckConfig Tests
    // ========================================================================

    #[test]
    fn test_crossy_deck_config_easy() {
        let config = CrossyDeckConfig::easy();
        assert_eq!(config.survive_count, 20);
        assert_eq!(config.hit_count, 5);
        assert_eq!(config.total_cards(), 25);
    }

    #[test]
    fn test_crossy_deck_config_medium() {
        let config = CrossyDeckConfig::medium();
        assert_eq!(config.survive_count, 15);
        assert_eq!(config.hit_count, 10);
        assert_eq!(config.total_cards(), 25);
    }

    #[test]
    fn test_crossy_deck_config_hard() {
        let config = CrossyDeckConfig::hard();
        assert_eq!(config.survive_count, 10);
        assert_eq!(config.hit_count, 15);
        assert_eq!(config.total_cards(), 25);
    }

    #[test]
    fn test_crossy_deck_config_daredevil() {
        let config = CrossyDeckConfig::daredevil();
        assert_eq!(config.survive_count, 5);
        assert_eq!(config.hit_count, 20);
        assert_eq!(config.total_cards(), 25);
    }

    #[test]
    fn test_crossy_deck_config_custom() {
        let config = CrossyDeckConfig::new(30, 20);
        assert_eq!(config.survive_count, 30);
        assert_eq!(config.hit_count, 20);
        assert_eq!(config.total_cards(), 50);
    }

    #[test]
    fn test_crossy_deck_config_survival_rate() {
        let easy = CrossyDeckConfig::easy();
        assert!((easy.survival_rate() - 0.8).abs() < 0.001);

        let medium = CrossyDeckConfig::medium();
        assert!((medium.survival_rate() - 0.6).abs() < 0.001);

        let hard = CrossyDeckConfig::hard();
        assert!((hard.survival_rate() - 0.4).abs() < 0.001);

        let daredevil = CrossyDeckConfig::daredevil();
        assert!((daredevil.survival_rate() - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_crossy_deck_config_validate_empty() {
        let config = CrossyDeckConfig::new(0, 0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_crossy_deck_config_validate_valid() {
        let config = CrossyDeckConfig::easy();
        assert!(config.validate().is_ok());
    }

    // ========================================================================
    // Card Index Tests
    // ========================================================================

    #[test]
    fn test_create_crossy_card_indices_easy() {
        let config = CrossyDeckConfig::easy();
        let indices = create_crossy_card_indices(&config);

        assert_eq!(indices.len(), 25);
        assert_eq!(indices.iter().filter(|&&i| i == 1).count(), 20); // Survive
        assert_eq!(indices.iter().filter(|&&i| i == 2).count(), 5); // Hit
    }

    #[test]
    fn test_create_crossy_card_indices_distribution() {
        for config in [
            CrossyDeckConfig::easy(),
            CrossyDeckConfig::medium(),
            CrossyDeckConfig::hard(),
            CrossyDeckConfig::daredevil(),
        ] {
            let indices = create_crossy_card_indices(&config);
            let survive_count = indices.iter().filter(|&&i| i == 1).count();
            let hit_count = indices.iter().filter(|&&i| i == 2).count();

            assert_eq!(survive_count, config.survive_count as usize);
            assert_eq!(hit_count, config.hit_count as usize);
            assert_eq!(indices.len(), config.total_cards() as usize);
        }
    }

    #[test]
    fn test_resolve_crossy_card_type_survive() {
        let card_type = resolve_crossy_card_type(1).unwrap();
        assert_eq!(card_type, CrossyCardType::Survive);
    }

    #[test]
    fn test_resolve_crossy_card_type_hit() {
        let card_type = resolve_crossy_card_type(2).unwrap();
        assert_eq!(card_type, CrossyCardType::Hit);
    }

    #[test]
    fn test_resolve_crossy_card_type_invalid_zero() {
        assert!(resolve_crossy_card_type(0).is_err());
    }

    #[test]
    fn test_resolve_crossy_card_type_invalid_three() {
        assert!(resolve_crossy_card_type(3).is_err());
    }

    #[test]
    fn test_resolve_crossy_card_type_invalid_large() {
        assert!(resolve_crossy_card_type(100).is_err());
    }

    // ========================================================================
    // Card Creation Tests
    // ========================================================================

    #[test]
    fn test_create_crossy_cards() {
        let config = CrossyDeckConfig::easy();
        let cards = create_crossy_cards(&config);

        assert_eq!(cards.len(), 25);

        // Verify all cards are either index 1 or 2
        let survive_card = Card::from_index(1);
        let hit_card = Card::from_index(2);

        let survive_count = cards
            .iter()
            .filter(|c| c.point == survive_card.point)
            .count();
        let hit_count = cards.iter().filter(|c| c.point == hit_card.point).count();

        assert_eq!(survive_count, 20);
        assert_eq!(hit_count, 5);
    }

    // ========================================================================
    // Game Utility Tests
    // ========================================================================

    #[test]
    fn test_get_card_index_for_lane_row0() {
        assert_eq!(get_card_index_for_lane(0, 1, 5), 0);
        assert_eq!(get_card_index_for_lane(0, 2, 5), 1);
        assert_eq!(get_card_index_for_lane(0, 3, 5), 2);
        assert_eq!(get_card_index_for_lane(0, 4, 5), 3);
        assert_eq!(get_card_index_for_lane(0, 5, 5), 4);
    }

    #[test]
    fn test_get_card_index_for_lane_row1() {
        assert_eq!(get_card_index_for_lane(1, 1, 5), 5);
        assert_eq!(get_card_index_for_lane(1, 3, 5), 7);
        assert_eq!(get_card_index_for_lane(1, 5, 5), 9);
    }

    #[test]
    fn test_get_card_index_for_lane_various_rows() {
        assert_eq!(get_card_index_for_lane(2, 1, 5), 10);
        assert_eq!(get_card_index_for_lane(3, 1, 5), 15);
        assert_eq!(get_card_index_for_lane(4, 1, 5), 20);
    }

    #[test]
    fn test_calculate_multiplier() {
        assert_eq!(calculate_multiplier(0, 1.0, 0.25), 1.0);
        assert_eq!(calculate_multiplier(1, 1.0, 0.25), 1.25);
        assert_eq!(calculate_multiplier(2, 1.0, 0.25), 1.5);
        assert_eq!(calculate_multiplier(4, 1.0, 0.25), 2.0);
    }

    #[test]
    fn test_calculate_multiplier_custom_base() {
        assert_eq!(calculate_multiplier(0, 1.5, 0.5), 1.5);
        assert_eq!(calculate_multiplier(2, 1.5, 0.5), 2.5);
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[test]
    fn test_crossy_deck_masking() {
        let config = CrossyDeckConfig::easy();
        let cards = create_crossy_cards(&config);

        // Generate keys for two-party game
        let (pk1, _sk1) = MentalPokerProtocol::player_keygen();
        let (pk2, _sk2) = MentalPokerProtocol::player_keygen();
        let aggregate_pk = pk1.add(&pk2);

        // Mask all cards
        for card in &cards {
            let (masked, _proof) = MentalPokerProtocol::mask(card, &aggregate_pk, None).unwrap();
            // Verify masking succeeded
            assert_ne!(masked.c0, masked.c1);
        }
    }

    #[test]
    fn test_full_crossy_two_party_flow() {
        // Setup: Two parties (player and house)
        let (pk1, sk1) = MentalPokerProtocol::player_keygen();
        let (pk2, sk2) = MentalPokerProtocol::player_keygen();
        let aggregate_pk = pk1.add(&pk2);

        // Create and mask a simple crossy deck
        let config = CrossyDeckConfig::new(3, 2); // 3 survive, 2 hit
        let cards = create_crossy_cards(&config);

        // Mask all cards
        let mut masked_cards = Vec::new();
        for card in &cards {
            let (masked, _) = MentalPokerProtocol::mask(card, &aggregate_pk, None).unwrap();
            masked_cards.push(masked);
        }

        // Reveal a specific card (simulate lane selection)
        let card_index = 0; // First card
        let masked = &masked_cards[card_index];

        // Both parties compute reveal tokens
        let (token1, proof1) =
            MentalPokerProtocol::compute_reveal_token(masked, &sk1, &pk1).unwrap();
        let (token2, proof2) =
            MentalPokerProtocol::compute_reveal_token(masked, &sk2, &pk2).unwrap();

        // Unmask the card
        let tokens = vec![(token1, proof1, pk1), (token2, proof2, pk2)];
        let revealed = MentalPokerProtocol::unmask(masked, &tokens).unwrap();

        // The revealed card should match one of our original cards
        let survive_card = Card::from_index(1);
        let hit_card = Card::from_index(2);

        let is_survive = revealed.point == survive_card.point;
        let is_hit = revealed.point == hit_card.point;

        assert!(
            is_survive || is_hit,
            "Revealed card must be either Survive or Hit"
        );
    }

    #[test]
    fn test_crossy_card_encoding_roundtrip() {
        // Test that we can encode and decode crossy cards consistently
        for card_type in [CrossyCardType::Survive, CrossyCardType::Hit] {
            let index = card_type.index();
            let resolved = resolve_crossy_card_type(index).unwrap();
            assert_eq!(resolved, card_type);
        }
    }
}
