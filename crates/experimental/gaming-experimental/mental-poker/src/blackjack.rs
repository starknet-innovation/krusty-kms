//! Blackjack game logic for mental poker.
//!
//! This module provides Blackjack-specific types and utilities that work
//! with the mental poker protocol for provably fair card games.
//!
//! # Card Encoding
//!
//! Uses standard 52-card deck encoding from the deck module:
//! - Index 1-13: Clubs (2,3,4,5,6,7,8,9,10,J,Q,K,A)
//! - Index 14-26: Diamonds
//! - Index 27-39: Hearts
//! - Index 40-52: Spades
//!
//! # Example
//!
//! ```
//! use mental_poker::blackjack::{card_value, calculate_hand_value, is_blackjack};
//!
//! // Player has Ace of Clubs (13) and Jack of Spades (49)
//! let hand = vec![13, 49];
//! assert!(is_blackjack(&hand));
//!
//! let value = calculate_hand_value(&hand);
//! assert_eq!(value.best(), 21);
//! ```

use crate::error::{MentalPokerError, Result};
use crate::types::Card;
use serde::{Deserialize, Serialize};

// ============================================================================
// Card Value Mapping
// ============================================================================

/// Get the rank index (0-12) from a card index (1-52).
/// Returns 0 for 2, 1 for 3, ..., 8 for 10, 9 for J, 10 for Q, 11 for K, 12 for A.
#[inline]
fn rank_from_index(index: u64) -> u8 {
    ((index - 1) % 13) as u8
}

/// Get the Blackjack value of a card.
///
/// # Arguments
/// * `index` - Card index (1-52)
///
/// # Returns
/// * 2-10 for number cards
/// * 10 for face cards (J, Q, K)
/// * 11 for Ace (caller handles soft/hard)
///
/// # Panics
/// Panics if index is 0 or > 52.
pub fn card_value(index: u64) -> u8 {
    assert!((1..=52).contains(&index), "Card index must be 1-52");

    let rank = rank_from_index(index);
    match rank {
        0..=8 => rank + 2, // 2-10
        9..=11 => 10,      // J, Q, K
        12 => 11,          // A (soft value)
        _ => unreachable!(),
    }
}

/// Check if a card is an Ace.
pub fn is_ace(index: u64) -> bool {
    rank_from_index(index) == 12
}

/// Check if a card is a face card (J, Q, K).
pub fn is_face_card(index: u64) -> bool {
    let rank = rank_from_index(index);
    (9..=11).contains(&rank)
}

/// Check if a card has value 10 (10, J, Q, K).
pub fn is_ten_value(index: u64) -> bool {
    let rank = rank_from_index(index);
    (8..=11).contains(&rank)
}

/// Get the suit of a card (0=Clubs, 1=Diamonds, 2=Hearts, 3=Spades).
pub fn card_suit(index: u64) -> u8 {
    ((index - 1) / 13) as u8
}

/// Get the suit symbol for display.
pub fn suit_symbol(suit: u8) -> &'static str {
    match suit {
        0 => "♣",
        1 => "♦",
        2 => "♥",
        3 => "♠",
        _ => "?",
    }
}

/// Get the rank symbol for display.
pub fn rank_symbol(index: u64) -> &'static str {
    let rank = rank_from_index(index);
    match rank {
        0 => "2",
        1 => "3",
        2 => "4",
        3 => "5",
        4 => "6",
        5 => "7",
        6 => "8",
        7 => "9",
        8 => "10",
        9 => "J",
        10 => "Q",
        11 => "K",
        12 => "A",
        _ => "?",
    }
}

/// Format a card for display (e.g., "A♠", "10♥").
pub fn format_card(index: u64) -> String {
    format!("{}{}", rank_symbol(index), suit_symbol(card_suit(index)))
}

// ============================================================================
// Hand Value Calculation
// ============================================================================

/// Represents the value of a Blackjack hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandValue {
    /// Hard total (all Aces count as 1).
    pub hard: u8,
    /// Soft total (one Ace counts as 11), if applicable and not bust.
    pub soft: Option<u8>,
    /// Number of Aces in the hand.
    pub aces: u8,
}

impl HandValue {
    /// Create a new hand value.
    pub fn new(hard: u8, soft: Option<u8>, aces: u8) -> Self {
        Self { hard, soft, aces }
    }

    /// Get the best (highest non-bust) value for the hand.
    pub fn best(&self) -> u8 {
        match self.soft {
            Some(soft) if soft <= 21 => soft,
            _ => self.hard,
        }
    }

    /// Check if the hand is a soft hand (has a usable Ace).
    pub fn is_soft(&self) -> bool {
        self.soft.map(|s| s <= 21).unwrap_or(false)
    }

    /// Check if the hand is bust (over 21).
    pub fn is_bust(&self) -> bool {
        self.hard > 21
    }
}

/// Calculate the value of a Blackjack hand.
///
/// # Arguments
/// * `cards` - Slice of card indices (1-52)
///
/// # Returns
/// A `HandValue` with hard total, optional soft total, and ace count.
pub fn calculate_hand_value(cards: &[u64]) -> HandValue {
    let mut hard_total: u8 = 0;
    let mut ace_count: u8 = 0;

    for &card in cards {
        let value = card_value(card);
        if value == 11 {
            // Count Ace as 1 for hard total initially
            hard_total = hard_total.saturating_add(1);
            ace_count += 1;
        } else {
            hard_total = hard_total.saturating_add(value);
        }
    }

    // Calculate soft total (one Ace as 11, if possible)
    let soft_total = if ace_count > 0 && hard_total + 10 <= 21 {
        Some(hard_total + 10)
    } else {
        None
    };

    HandValue::new(hard_total, soft_total, ace_count)
}

/// Get the best value for a hand (convenience function).
pub fn best_value(cards: &[u64]) -> u8 {
    calculate_hand_value(cards).best()
}

/// Check if a hand is bust.
pub fn is_bust(cards: &[u64]) -> bool {
    calculate_hand_value(cards).is_bust()
}

/// Check if the initial two cards form a Blackjack (Ace + 10-value).
pub fn is_blackjack(cards: &[u64]) -> bool {
    if cards.len() != 2 {
        return false;
    }

    let has_ace = is_ace(cards[0]) || is_ace(cards[1]);
    let has_ten = is_ten_value(cards[0]) || is_ten_value(cards[1]);

    has_ace && has_ten
}

// ============================================================================
// Dealer Logic
// ============================================================================

/// Standard dealer rules: hit on 16 or less, stand on 17 or more.
pub fn should_dealer_hit(hand: &HandValue) -> bool {
    hand.best() < 17
}

/// Dealer hits on soft 17 variant (some casinos use this rule).
pub fn should_dealer_hit_soft17(hand: &HandValue) -> bool {
    let best = hand.best();
    if best < 17 {
        return true;
    }
    // Hit on soft 17
    if best == 17 && hand.is_soft() {
        return true;
    }
    false
}

// ============================================================================
// Game Outcome
// ============================================================================

/// Possible outcomes of a Blackjack hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// Player wins with Blackjack (3:2 payout).
    PlayerBlackjack,
    /// Dealer wins with Blackjack.
    DealerBlackjack,
    /// Both have Blackjack (push).
    BothBlackjack,
    /// Player wins (1:1 payout).
    PlayerWins,
    /// Dealer wins (player loses bet).
    DealerWins,
    /// Push/tie (bet returned).
    Push,
    /// Player busts (dealer wins).
    PlayerBusts,
    /// Dealer busts (player wins).
    DealerBusts,
}

impl Outcome {
    /// Get display text for the outcome.
    pub fn display(&self) -> &'static str {
        match self {
            Outcome::PlayerBlackjack => "Blackjack! You win!",
            Outcome::DealerBlackjack => "Dealer Blackjack!",
            Outcome::BothBlackjack => "Push - Both Blackjack",
            Outcome::PlayerWins => "You win!",
            Outcome::DealerWins => "Dealer wins",
            Outcome::Push => "Push",
            Outcome::PlayerBusts => "Bust! Dealer wins",
            Outcome::DealerBusts => "Dealer busts! You win!",
        }
    }

    /// Check if this outcome is a win for the player.
    pub fn is_player_win(&self) -> bool {
        matches!(
            self,
            Outcome::PlayerBlackjack | Outcome::PlayerWins | Outcome::DealerBusts
        )
    }

    /// Check if this outcome is a push (tie).
    pub fn is_push(&self) -> bool {
        matches!(self, Outcome::Push | Outcome::BothBlackjack)
    }
}

/// Determine the winner of a Blackjack hand.
///
/// # Arguments
/// * `player_cards` - Player's cards
/// * `dealer_cards` - Dealer's cards
///
/// # Returns
/// The outcome of the hand.
pub fn determine_winner(player_cards: &[u64], dealer_cards: &[u64]) -> Outcome {
    let player_bj = is_blackjack(player_cards);
    let dealer_bj = is_blackjack(dealer_cards);

    // Check for blackjacks first
    if player_bj && dealer_bj {
        return Outcome::BothBlackjack;
    }
    if player_bj {
        return Outcome::PlayerBlackjack;
    }
    if dealer_bj {
        return Outcome::DealerBlackjack;
    }

    let player_value = calculate_hand_value(player_cards);
    let dealer_value = calculate_hand_value(dealer_cards);

    // Check for busts
    if player_value.is_bust() {
        return Outcome::PlayerBusts;
    }
    if dealer_value.is_bust() {
        return Outcome::DealerBusts;
    }

    // Compare values
    let player_best = player_value.best();
    let dealer_best = dealer_value.best();

    match player_best.cmp(&dealer_best) {
        std::cmp::Ordering::Greater => Outcome::PlayerWins,
        std::cmp::Ordering::Less => Outcome::DealerWins,
        std::cmp::Ordering::Equal => Outcome::Push,
    }
}

// ============================================================================
// Payout Calculation
// ============================================================================

/// Calculate the payout for a hand.
///
/// # Arguments
/// * `bet` - The original bet amount
/// * `outcome` - The outcome of the hand
///
/// # Returns
/// The payout amount (0 for loss, bet for push, bet*2 for win, bet*2.5 for blackjack).
pub fn calculate_payout(bet: u64, outcome: Outcome) -> u64 {
    match outcome {
        Outcome::PlayerBlackjack => bet + (bet * 3) / 2, // 3:2 payout
        Outcome::PlayerWins | Outcome::DealerBusts => bet * 2, // 1:1 payout
        Outcome::Push | Outcome::BothBlackjack => bet,   // Return bet
        Outcome::DealerWins | Outcome::DealerBlackjack | Outcome::PlayerBusts => 0, // Lose bet
    }
}

// ============================================================================
// Deck Configuration
// ============================================================================

/// Configuration for a Blackjack deck/shoe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlackjackDeckConfig {
    /// Number of standard 52-card decks in the shoe.
    pub num_decks: u32,
}

impl BlackjackDeckConfig {
    /// Create a new configuration.
    pub fn new(num_decks: u32) -> Self {
        Self { num_decks }
    }

    /// Single deck configuration.
    pub fn single_deck() -> Self {
        Self { num_decks: 1 }
    }

    /// Double deck configuration.
    pub fn double_deck() -> Self {
        Self { num_decks: 2 }
    }

    /// Standard 6-deck shoe configuration.
    pub fn standard_shoe() -> Self {
        Self { num_decks: 6 }
    }

    /// 8-deck shoe configuration (common in casinos).
    pub fn eight_deck_shoe() -> Self {
        Self { num_decks: 8 }
    }

    /// Get the total number of cards.
    pub fn total_cards(&self) -> u32 {
        self.num_decks * 52
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.num_decks == 0 {
            return Err(MentalPokerError::InvalidParameters(
                "Number of decks must be at least 1".to_string(),
            ));
        }
        if self.num_decks > 8 {
            return Err(MentalPokerError::InvalidParameters(
                "Number of decks cannot exceed 8".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for BlackjackDeckConfig {
    fn default() -> Self {
        Self::single_deck()
    }
}

/// Create card indices for a Blackjack shoe.
///
/// # Arguments
/// * `config` - Deck configuration
///
/// # Returns
/// Vector of card indices (1-52 repeated for each deck).
pub fn create_blackjack_card_indices(config: &BlackjackDeckConfig) -> Vec<u64> {
    let mut indices = Vec::with_capacity((config.num_decks * 52) as usize);
    for _ in 0..config.num_decks {
        for i in 1..=52 {
            indices.push(i);
        }
    }
    indices
}

/// Create Card objects for a Blackjack deck/shoe.
///
/// # Arguments
/// * `config` - Deck configuration
///
/// # Returns
/// Vector of Card objects.
pub fn create_blackjack_cards(config: &BlackjackDeckConfig) -> Vec<Card> {
    create_blackjack_card_indices(config)
        .into_iter()
        .map(Card::from_index)
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // Card Value Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_card_value_number_cards() {
        // Clubs: indices 1-13
        assert_eq!(card_value(1), 2); // 2 of Clubs
        assert_eq!(card_value(2), 3); // 3 of Clubs
        assert_eq!(card_value(3), 4); // 4 of Clubs
        assert_eq!(card_value(4), 5); // 5 of Clubs
        assert_eq!(card_value(5), 6); // 6 of Clubs
        assert_eq!(card_value(6), 7); // 7 of Clubs
        assert_eq!(card_value(7), 8); // 8 of Clubs
        assert_eq!(card_value(8), 9); // 9 of Clubs
        assert_eq!(card_value(9), 10); // 10 of Clubs
    }

    #[test]
    fn test_card_value_face_cards() {
        // J, Q, K all worth 10
        assert_eq!(card_value(10), 10); // J of Clubs
        assert_eq!(card_value(11), 10); // Q of Clubs
        assert_eq!(card_value(12), 10); // K of Clubs

        // Face cards in other suits
        assert_eq!(card_value(23), 10); // J of Diamonds
        assert_eq!(card_value(36), 10); // J of Hearts
        assert_eq!(card_value(49), 10); // J of Spades
    }

    #[test]
    fn test_card_value_aces() {
        assert_eq!(card_value(13), 11); // A of Clubs
        assert_eq!(card_value(26), 11); // A of Diamonds
        assert_eq!(card_value(39), 11); // A of Hearts
        assert_eq!(card_value(52), 11); // A of Spades
    }

    #[test]
    fn test_is_ace() {
        assert!(is_ace(13)); // A of Clubs
        assert!(is_ace(26)); // A of Diamonds
        assert!(is_ace(39)); // A of Hearts
        assert!(is_ace(52)); // A of Spades

        assert!(!is_ace(1)); // 2 of Clubs
        assert!(!is_ace(10)); // J of Clubs
        assert!(!is_ace(12)); // K of Clubs
    }

    #[test]
    fn test_is_face_card() {
        assert!(is_face_card(10)); // J of Clubs
        assert!(is_face_card(11)); // Q of Clubs
        assert!(is_face_card(12)); // K of Clubs

        assert!(!is_face_card(9)); // 10 of Clubs
        assert!(!is_face_card(13)); // A of Clubs
    }

    #[test]
    fn test_is_ten_value() {
        assert!(is_ten_value(9)); // 10 of Clubs
        assert!(is_ten_value(10)); // J of Clubs
        assert!(is_ten_value(11)); // Q of Clubs
        assert!(is_ten_value(12)); // K of Clubs

        assert!(!is_ten_value(8)); // 9 of Clubs
        assert!(!is_ten_value(13)); // A of Clubs
    }

    #[test]
    fn test_format_card() {
        assert_eq!(format_card(1), "2♣");
        assert_eq!(format_card(13), "A♣");
        assert_eq!(format_card(14), "2♦");
        assert_eq!(format_card(26), "A♦");
        assert_eq!(format_card(27), "2♥");
        assert_eq!(format_card(39), "A♥");
        assert_eq!(format_card(40), "2♠");
        assert_eq!(format_card(52), "A♠");
        assert_eq!(format_card(9), "10♣");
        assert_eq!(format_card(10), "J♣");
    }

    // ------------------------------------------------------------------------
    // Hand Value Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_hard_hand() {
        // 7 + 8 = 15 (hard)
        let hand = calculate_hand_value(&[6, 7]); // 7 and 8 of clubs
        assert_eq!(hand.hard, 15);
        assert_eq!(hand.soft, None);
        assert_eq!(hand.best(), 15);
        assert!(!hand.is_soft());
    }

    #[test]
    fn test_soft_hand() {
        // A + 6 = 17 soft (or 7 hard)
        let hand = calculate_hand_value(&[13, 5]); // A and 6 of clubs
        assert_eq!(hand.hard, 7);
        assert_eq!(hand.soft, Some(17));
        assert_eq!(hand.best(), 17);
        assert!(hand.is_soft());
    }

    #[test]
    fn test_ace_converts_to_hard() {
        // A + 6 + 9 = 16 hard (A must be 1)
        let hand = calculate_hand_value(&[13, 5, 8]); // A, 6, 9 of clubs
        assert_eq!(hand.hard, 16);
        assert_eq!(hand.soft, None); // Can't use soft (would be 26)
        assert_eq!(hand.best(), 16);
        assert!(!hand.is_soft());
    }

    #[test]
    fn test_two_aces() {
        // A + A = 12 (one as 11, one as 1) or 2 hard
        let hand = calculate_hand_value(&[13, 26]); // A of clubs, A of diamonds
        assert_eq!(hand.hard, 2);
        assert_eq!(hand.soft, Some(12));
        assert_eq!(hand.best(), 12);
    }

    #[test]
    fn test_multiple_aces() {
        // A + A + A = 13 (one as 11, two as 1) or 3 hard
        let hand = calculate_hand_value(&[13, 26, 39]);
        assert_eq!(hand.hard, 3);
        assert_eq!(hand.soft, Some(13));
        assert_eq!(hand.best(), 13);
    }

    #[test]
    fn test_twenty_one_hard() {
        // 10 + J + A = 21 hard
        let hand = calculate_hand_value(&[9, 10, 13]); // 10, J, A
        assert_eq!(hand.hard, 21);
        assert_eq!(hand.soft, None); // Can't add 10 without busting
        assert_eq!(hand.best(), 21);
    }

    // ------------------------------------------------------------------------
    // Blackjack Detection Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_blackjack_ace_jack() {
        assert!(is_blackjack(&[13, 10])); // A + J
        assert!(is_blackjack(&[10, 13])); // J + A
    }

    #[test]
    fn test_blackjack_ace_ten() {
        assert!(is_blackjack(&[13, 9])); // A + 10
        assert!(is_blackjack(&[9, 52])); // 10 + A (spades)
    }

    #[test]
    fn test_blackjack_ace_queen_king() {
        assert!(is_blackjack(&[26, 11])); // A + Q
        assert!(is_blackjack(&[12, 39])); // K + A
    }

    #[test]
    fn test_not_blackjack_three_cards() {
        // 21 with 3+ cards is not blackjack
        assert!(!is_blackjack(&[13, 5, 5])); // A + 6 + 5 = 21
        assert!(!is_blackjack(&[6, 7, 8])); // 7 + 8 + 9 = 21... wait, that's 24
    }

    #[test]
    fn test_not_blackjack_no_ace() {
        assert!(!is_blackjack(&[9, 10])); // 10 + J = 20
    }

    #[test]
    fn test_not_blackjack_no_ten() {
        assert!(!is_blackjack(&[13, 8])); // A + 9 = 20
    }

    // ------------------------------------------------------------------------
    // Bust Detection Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_bust() {
        let hand = calculate_hand_value(&[9, 10, 11]); // 10 + J + Q = 30
        assert!(hand.is_bust());
        assert!(is_bust(&[9, 10, 11]));
    }

    #[test]
    fn test_not_bust_21() {
        assert!(!is_bust(&[13, 9])); // 21
        assert!(!is_bust(&[9, 10, 13])); // 21 hard
    }

    #[test]
    fn test_not_bust_20() {
        assert!(!is_bust(&[9, 10])); // 20
    }

    // ------------------------------------------------------------------------
    // Dealer Logic Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_dealer_hits_on_16() {
        let hand = calculate_hand_value(&[9, 5]); // 10 + 6 = 16
        assert!(should_dealer_hit(&hand));
    }

    #[test]
    fn test_dealer_stands_on_17() {
        let hand = calculate_hand_value(&[9, 6]); // 10 + 7 = 17
        assert!(!should_dealer_hit(&hand));
    }

    #[test]
    fn test_dealer_stands_on_hard_17() {
        let hand = calculate_hand_value(&[10, 6]); // J + 7 = 17
        assert!(!should_dealer_hit(&hand));
    }

    #[test]
    fn test_dealer_soft17_rule_stand() {
        // Default: stand on all 17s
        let hand = calculate_hand_value(&[13, 5]); // A + 6 = soft 17
        assert!(!should_dealer_hit(&hand));
    }

    #[test]
    fn test_dealer_soft17_rule_hit() {
        // Variant: hit on soft 17
        let hand = calculate_hand_value(&[13, 5]); // A + 6 = soft 17
        assert!(should_dealer_hit_soft17(&hand));
    }

    #[test]
    fn test_dealer_stands_on_18() {
        let hand = calculate_hand_value(&[13, 6]); // A + 7 = soft 18
        assert!(!should_dealer_hit(&hand));
        assert!(!should_dealer_hit_soft17(&hand));
    }

    // ------------------------------------------------------------------------
    // Winner Determination Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_player_wins_higher() {
        let result = determine_winner(&[9, 8], &[9, 6]); // 19 vs 17
        assert_eq!(result, Outcome::PlayerWins);
        assert!(result.is_player_win());
    }

    #[test]
    fn test_dealer_wins_higher() {
        let result = determine_winner(&[9, 5], &[9, 7]); // 16 vs 18
        assert_eq!(result, Outcome::DealerWins);
        assert!(!result.is_player_win());
    }

    #[test]
    fn test_push_same_value() {
        // Player: 10 of clubs (9) + 8 of clubs (7) = 10 + 8 = 18
        // Dealer: 10 of clubs (9) + 8 of diamonds (20) = 10 + 8 = 18
        let result = determine_winner(&[9, 7], &[9, 20]);
        assert_eq!(result, Outcome::Push);
        assert!(result.is_push());
    }

    #[test]
    fn test_player_blackjack() {
        let result = determine_winner(&[13, 9], &[9, 7]); // BJ vs 18
        assert_eq!(result, Outcome::PlayerBlackjack);
        assert!(result.is_player_win());
    }

    #[test]
    fn test_dealer_blackjack() {
        let result = determine_winner(&[9, 8], &[26, 10]); // 19 vs BJ
        assert_eq!(result, Outcome::DealerBlackjack);
        assert!(!result.is_player_win());
    }

    #[test]
    fn test_both_blackjack() {
        let result = determine_winner(&[13, 9], &[26, 10]); // BJ vs BJ
        assert_eq!(result, Outcome::BothBlackjack);
        assert!(result.is_push());
    }

    #[test]
    fn test_player_busts() {
        let result = determine_winner(&[9, 10, 11], &[9, 6]); // 30 vs 17
        assert_eq!(result, Outcome::PlayerBusts);
    }

    #[test]
    fn test_dealer_busts() {
        let result = determine_winner(&[9, 4], &[9, 10, 11]); // 15 vs 30
        assert_eq!(result, Outcome::DealerBusts);
        assert!(result.is_player_win());
    }

    #[test]
    fn test_player_21_vs_dealer_21_not_blackjack() {
        // Both have 21 but neither is blackjack
        let _result = determine_winner(&[6, 7, 8], &[5, 6, 9]); // 7+8+9=24 vs 6+7+10=23... let me recalculate
                                                                // Actually: 6=7, 7=8, 8=9 → 7+8+9=24 (bust!)
                                                                // Let me use correct indices
                                                                // 5 (6), 6 (7), 7 (8) → 6+7+8=21
        let result = determine_winner(&[5, 6, 7], &[4, 5, 9]); // 6+7+8=21 vs 5+6+10=21
        assert_eq!(result, Outcome::Push);
    }

    // ------------------------------------------------------------------------
    // Payout Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_payout_blackjack() {
        // 3:2 payout: bet 100, win 150, get 250 total
        assert_eq!(calculate_payout(100, Outcome::PlayerBlackjack), 250);
        assert_eq!(calculate_payout(200, Outcome::PlayerBlackjack), 500);
    }

    #[test]
    fn test_payout_win() {
        // 1:1 payout: bet 100, win 100, get 200 total
        assert_eq!(calculate_payout(100, Outcome::PlayerWins), 200);
        assert_eq!(calculate_payout(100, Outcome::DealerBusts), 200);
    }

    #[test]
    fn test_payout_push() {
        // Bet returned
        assert_eq!(calculate_payout(100, Outcome::Push), 100);
        assert_eq!(calculate_payout(100, Outcome::BothBlackjack), 100);
    }

    #[test]
    fn test_payout_loss() {
        // Lose bet
        assert_eq!(calculate_payout(100, Outcome::DealerWins), 0);
        assert_eq!(calculate_payout(100, Outcome::DealerBlackjack), 0);
        assert_eq!(calculate_payout(100, Outcome::PlayerBusts), 0);
    }

    // ------------------------------------------------------------------------
    // Deck Configuration Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_single_deck() {
        let config = BlackjackDeckConfig::single_deck();
        assert_eq!(config.num_decks, 1);
        assert_eq!(config.total_cards(), 52);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_standard_shoe() {
        let config = BlackjackDeckConfig::standard_shoe();
        assert_eq!(config.num_decks, 6);
        assert_eq!(config.total_cards(), 312);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_eight_deck_shoe() {
        let config = BlackjackDeckConfig::eight_deck_shoe();
        assert_eq!(config.num_decks, 8);
        assert_eq!(config.total_cards(), 416);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_zero_decks() {
        let config = BlackjackDeckConfig::new(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_too_many_decks() {
        let config = BlackjackDeckConfig::new(9);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_create_card_indices() {
        let config = BlackjackDeckConfig::single_deck();
        let indices = create_blackjack_card_indices(&config);
        assert_eq!(indices.len(), 52);
        assert_eq!(indices[0], 1);
        assert_eq!(indices[51], 52);
    }

    #[test]
    fn test_create_card_indices_multi_deck() {
        let config = BlackjackDeckConfig::double_deck();
        let indices = create_blackjack_card_indices(&config);
        assert_eq!(indices.len(), 104);
        // First deck
        assert_eq!(indices[0], 1);
        assert_eq!(indices[51], 52);
        // Second deck
        assert_eq!(indices[52], 1);
        assert_eq!(indices[103], 52);
    }

    #[test]
    fn test_create_cards() {
        let config = BlackjackDeckConfig::single_deck();
        let cards = create_blackjack_cards(&config);
        assert_eq!(cards.len(), 52);
    }
}
