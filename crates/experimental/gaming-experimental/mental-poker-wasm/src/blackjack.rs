//! Blackjack game WASM bindings.
//!
//! WebAssembly bindings for Blackjack game primitives, providing
//! provably fair card game logic for browser environments.

use crate::deck::WasmDeck;
use mental_poker::blackjack::{
    best_value, calculate_hand_value, calculate_payout, card_suit, card_value,
    create_blackjack_card_indices, create_blackjack_cards, determine_winner, format_card, is_ace,
    is_blackjack, is_bust, is_face_card, is_ten_value, rank_symbol, should_dealer_hit,
    should_dealer_hit_soft17, suit_symbol, BlackjackDeckConfig, HandValue, Outcome,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ============================================================================
// Deck Configuration
// ============================================================================

/// Configuration for a Blackjack deck/shoe.
///
/// Determines the number of standard 52-card decks in the shoe.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmBlackjackDeckConfig {
    /// Number of standard 52-card decks in the shoe.
    pub num_decks: u32,
}

#[wasm_bindgen]
impl WasmBlackjackDeckConfig {
    /// Create a new deck configuration with custom number of decks.
    #[wasm_bindgen(constructor)]
    pub fn new(num_decks: u32) -> Self {
        Self { num_decks }
    }

    /// Single deck configuration.
    #[wasm_bindgen(js_name = "singleDeck")]
    pub fn single_deck() -> Self {
        let config = BlackjackDeckConfig::single_deck();
        Self {
            num_decks: config.num_decks,
        }
    }

    /// Double deck configuration.
    #[wasm_bindgen(js_name = "doubleDeck")]
    pub fn double_deck() -> Self {
        let config = BlackjackDeckConfig::double_deck();
        Self {
            num_decks: config.num_decks,
        }
    }

    /// Standard 6-deck shoe configuration.
    #[wasm_bindgen(js_name = "standardShoe")]
    pub fn standard_shoe() -> Self {
        let config = BlackjackDeckConfig::standard_shoe();
        Self {
            num_decks: config.num_decks,
        }
    }

    /// 8-deck shoe configuration (common in casinos).
    #[wasm_bindgen(js_name = "eightDeckShoe")]
    pub fn eight_deck_shoe() -> Self {
        let config = BlackjackDeckConfig::eight_deck_shoe();
        Self {
            num_decks: config.num_decks,
        }
    }

    /// Get the total number of cards in the shoe.
    #[wasm_bindgen(js_name = "totalCards")]
    pub fn total_cards(&self) -> u32 {
        self.num_decks * 52
    }

    /// Validate the configuration.
    #[wasm_bindgen]
    pub fn validate(&self) -> Result<(), JsValue> {
        let config = self.to_native();
        config
            .validate()
            .map_err(|e| JsValue::from_str(&format!("Invalid config: {}", e)))
    }

    /// Convert to native BlackjackDeckConfig.
    fn to_native(&self) -> BlackjackDeckConfig {
        BlackjackDeckConfig::new(self.num_decks)
    }
}

// ============================================================================
// Hand Value
// ============================================================================

/// Represents the value of a Blackjack hand.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmHandValue {
    /// Hard total (all Aces count as 1).
    pub hard: u8,
    /// Soft total (one Ace counts as 11), if applicable.
    pub soft: Option<u8>,
    /// Number of Aces in the hand.
    pub aces: u8,
}

#[wasm_bindgen]
impl WasmHandValue {
    /// Get the best (highest non-bust) value for the hand.
    #[wasm_bindgen]
    pub fn best(&self) -> u8 {
        match self.soft {
            Some(soft) if soft <= 21 => soft,
            _ => self.hard,
        }
    }

    /// Check if the hand is a soft hand (has a usable Ace).
    #[wasm_bindgen(js_name = "isSoft")]
    pub fn is_soft(&self) -> bool {
        self.soft.map(|s| s <= 21).unwrap_or(false)
    }

    /// Check if the hand is bust (over 21).
    #[wasm_bindgen(js_name = "isBust")]
    pub fn is_bust(&self) -> bool {
        self.hard > 21
    }
}

impl From<HandValue> for WasmHandValue {
    fn from(hv: HandValue) -> Self {
        Self {
            hard: hv.hard,
            soft: hv.soft,
            aces: hv.aces,
        }
    }
}

// ============================================================================
// Game Outcome
// ============================================================================

/// Possible outcomes of a Blackjack hand.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmBlackjackOutcome {
    /// Player wins with Blackjack (3:2 payout).
    PlayerBlackjack = 0,
    /// Dealer wins with Blackjack.
    DealerBlackjack = 1,
    /// Both have Blackjack (push).
    BothBlackjack = 2,
    /// Player wins (1:1 payout).
    PlayerWins = 3,
    /// Dealer wins (player loses bet).
    DealerWins = 4,
    /// Push/tie (bet returned).
    Push = 5,
    /// Player busts (dealer wins).
    PlayerBusts = 6,
    /// Dealer busts (player wins).
    DealerBusts = 7,
}

impl From<Outcome> for WasmBlackjackOutcome {
    fn from(o: Outcome) -> Self {
        match o {
            Outcome::PlayerBlackjack => WasmBlackjackOutcome::PlayerBlackjack,
            Outcome::DealerBlackjack => WasmBlackjackOutcome::DealerBlackjack,
            Outcome::BothBlackjack => WasmBlackjackOutcome::BothBlackjack,
            Outcome::PlayerWins => WasmBlackjackOutcome::PlayerWins,
            Outcome::DealerWins => WasmBlackjackOutcome::DealerWins,
            Outcome::Push => WasmBlackjackOutcome::Push,
            Outcome::PlayerBusts => WasmBlackjackOutcome::PlayerBusts,
            Outcome::DealerBusts => WasmBlackjackOutcome::DealerBusts,
        }
    }
}

impl From<WasmBlackjackOutcome> for Outcome {
    fn from(o: WasmBlackjackOutcome) -> Self {
        match o {
            WasmBlackjackOutcome::PlayerBlackjack => Outcome::PlayerBlackjack,
            WasmBlackjackOutcome::DealerBlackjack => Outcome::DealerBlackjack,
            WasmBlackjackOutcome::BothBlackjack => Outcome::BothBlackjack,
            WasmBlackjackOutcome::PlayerWins => Outcome::PlayerWins,
            WasmBlackjackOutcome::DealerWins => Outcome::DealerWins,
            WasmBlackjackOutcome::Push => Outcome::Push,
            WasmBlackjackOutcome::PlayerBusts => Outcome::PlayerBusts,
            WasmBlackjackOutcome::DealerBusts => Outcome::DealerBusts,
        }
    }
}

// ============================================================================
// Card Utilities
// ============================================================================

/// Get the Blackjack value of a card.
///
/// # Arguments
/// * `card_index` - Card index (1-52)
///
/// # Returns
/// * 2-10 for number cards
/// * 10 for face cards (J, Q, K)
/// * 11 for Ace (caller handles soft/hard)
#[wasm_bindgen(js_name = "blackjackCardValue")]
pub fn blackjack_card_value(card_index: u32) -> Result<u8, JsValue> {
    if !(1..=52).contains(&card_index) {
        return Err(JsValue::from_str("Card index must be 1-52"));
    }
    Ok(card_value(card_index as u64))
}

/// Check if a card is an Ace.
#[wasm_bindgen(js_name = "isBlackjackAce")]
pub fn is_blackjack_ace(card_index: u32) -> bool {
    if !(1..=52).contains(&card_index) {
        return false;
    }
    is_ace(card_index as u64)
}

/// Check if a card is a face card (J, Q, K).
#[wasm_bindgen(js_name = "isBlackjackFaceCard")]
pub fn is_blackjack_face_card(card_index: u32) -> bool {
    if !(1..=52).contains(&card_index) {
        return false;
    }
    is_face_card(card_index as u64)
}

/// Check if a card has value 10 (10, J, Q, K).
#[wasm_bindgen(js_name = "isBlackjackTenValue")]
pub fn is_blackjack_ten_value(card_index: u32) -> bool {
    if !(1..=52).contains(&card_index) {
        return false;
    }
    is_ten_value(card_index as u64)
}

/// Get the suit of a card (0=Clubs, 1=Diamonds, 2=Hearts, 3=Spades).
#[wasm_bindgen(js_name = "blackjackCardSuit")]
pub fn blackjack_card_suit(card_index: u32) -> Result<u8, JsValue> {
    if !(1..=52).contains(&card_index) {
        return Err(JsValue::from_str("Card index must be 1-52"));
    }
    Ok(card_suit(card_index as u64))
}

/// Get the rank symbol for display (e.g., "A", "K", "10", "2").
#[wasm_bindgen(js_name = "blackjackRankSymbol")]
pub fn blackjack_rank_symbol(card_index: u32) -> Result<String, JsValue> {
    if !(1..=52).contains(&card_index) {
        return Err(JsValue::from_str("Card index must be 1-52"));
    }
    Ok(rank_symbol(card_index as u64).to_string())
}

/// Get the suit symbol for display (♣, ♦, ♥, ♠).
#[wasm_bindgen(js_name = "blackjackSuitSymbol")]
pub fn blackjack_suit_symbol(suit: u8) -> String {
    suit_symbol(suit).to_string()
}

/// Format a card for display (e.g., "A♠", "10♥").
#[wasm_bindgen(js_name = "formatBlackjackCard")]
pub fn format_blackjack_card(card_index: u32) -> Result<String, JsValue> {
    if !(1..=52).contains(&card_index) {
        return Err(JsValue::from_str("Card index must be 1-52"));
    }
    Ok(format_card(card_index as u64))
}

// ============================================================================
// Hand Evaluation
// ============================================================================

/// Calculate the value of a Blackjack hand.
///
/// # Arguments
/// * `card_indices` - Array of card indices (1-52)
///
/// # Returns
/// A `WasmHandValue` with hard total, optional soft total, and ace count.
#[wasm_bindgen(js_name = "calculateBlackjackHandValue")]
pub fn calculate_blackjack_hand_value(card_indices: &[u32]) -> Result<WasmHandValue, JsValue> {
    let indices: Vec<u64> = card_indices.iter().map(|&i| i as u64).collect();
    for &idx in &indices {
        if !(1..=52).contains(&idx) {
            return Err(JsValue::from_str("All card indices must be 1-52"));
        }
    }
    Ok(calculate_hand_value(&indices).into())
}

/// Get the best value for a hand (convenience function).
#[wasm_bindgen(js_name = "blackjackBestValue")]
pub fn blackjack_best_value(card_indices: &[u32]) -> Result<u8, JsValue> {
    let indices: Vec<u64> = card_indices.iter().map(|&i| i as u64).collect();
    for &idx in &indices {
        if !(1..=52).contains(&idx) {
            return Err(JsValue::from_str("All card indices must be 1-52"));
        }
    }
    Ok(best_value(&indices))
}

/// Check if a hand is bust.
#[wasm_bindgen(js_name = "isBlackjackBust")]
pub fn is_blackjack_bust(card_indices: &[u32]) -> bool {
    let indices: Vec<u64> = card_indices.iter().map(|&i| i as u64).collect();
    is_bust(&indices)
}

/// Check if the initial two cards form a Blackjack (Ace + 10-value).
#[wasm_bindgen(js_name = "isBlackjack")]
pub fn is_blackjack_wasm(card_indices: &[u32]) -> bool {
    let indices: Vec<u64> = card_indices.iter().map(|&i| i as u64).collect();
    is_blackjack(&indices)
}

// ============================================================================
// Dealer Logic
// ============================================================================

/// Standard dealer rules: hit on 16 or less, stand on 17 or more.
#[wasm_bindgen(js_name = "shouldDealerHit")]
pub fn should_dealer_hit_wasm(card_indices: &[u32]) -> Result<bool, JsValue> {
    let indices: Vec<u64> = card_indices.iter().map(|&i| i as u64).collect();
    for &idx in &indices {
        if !(1..=52).contains(&idx) {
            return Err(JsValue::from_str("All card indices must be 1-52"));
        }
    }
    let hand = calculate_hand_value(&indices);
    Ok(should_dealer_hit(&hand))
}

/// Dealer hits on soft 17 variant (some casinos use this rule).
#[wasm_bindgen(js_name = "shouldDealerHitSoft17")]
pub fn should_dealer_hit_soft17_wasm(card_indices: &[u32]) -> Result<bool, JsValue> {
    let indices: Vec<u64> = card_indices.iter().map(|&i| i as u64).collect();
    for &idx in &indices {
        if !(1..=52).contains(&idx) {
            return Err(JsValue::from_str("All card indices must be 1-52"));
        }
    }
    let hand = calculate_hand_value(&indices);
    Ok(should_dealer_hit_soft17(&hand))
}

// ============================================================================
// Game Outcome
// ============================================================================

/// Determine the winner of a Blackjack hand.
///
/// # Arguments
/// * `player_cards` - Player's card indices
/// * `dealer_cards` - Dealer's card indices
///
/// # Returns
/// The outcome of the hand.
#[wasm_bindgen(js_name = "determineBlackjackWinner")]
pub fn determine_blackjack_winner(
    player_cards: &[u32],
    dealer_cards: &[u32],
) -> Result<WasmBlackjackOutcome, JsValue> {
    let player: Vec<u64> = player_cards.iter().map(|&i| i as u64).collect();
    let dealer: Vec<u64> = dealer_cards.iter().map(|&i| i as u64).collect();

    for &idx in player.iter().chain(dealer.iter()) {
        if !(1..=52).contains(&idx) {
            return Err(JsValue::from_str("All card indices must be 1-52"));
        }
    }

    Ok(determine_winner(&player, &dealer).into())
}

/// Get display text for an outcome.
#[wasm_bindgen(js_name = "blackjackOutcomeDisplay")]
pub fn blackjack_outcome_display(outcome: WasmBlackjackOutcome) -> String {
    let native: Outcome = outcome.into();
    native.display().to_string()
}

/// Check if an outcome is a win for the player.
#[wasm_bindgen(js_name = "isBlackjackPlayerWin")]
pub fn is_blackjack_player_win(outcome: WasmBlackjackOutcome) -> bool {
    let native: Outcome = outcome.into();
    native.is_player_win()
}

/// Check if an outcome is a push (tie).
#[wasm_bindgen(js_name = "isBlackjackPush")]
pub fn is_blackjack_push(outcome: WasmBlackjackOutcome) -> bool {
    let native: Outcome = outcome.into();
    native.is_push()
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
#[wasm_bindgen(js_name = "calculateBlackjackPayout")]
pub fn calculate_blackjack_payout(bet: u64, outcome: WasmBlackjackOutcome) -> u64 {
    let native: Outcome = outcome.into();
    calculate_payout(bet, native)
}

// ============================================================================
// Deck Creation
// ============================================================================

/// Create a Blackjack deck/shoe with the specified configuration.
///
/// Returns a WasmDeck with cards ordered: 1-52 repeated for each deck in the shoe.
/// The deck should be shuffled before use.
///
/// # Arguments
/// * `config` - The deck configuration specifying number of decks
///
/// # Example
/// ```typescript
/// const config = WasmBlackjackDeckConfig.singleDeck();
/// const deck = createBlackjackDeck(config);
/// console.log(deck.length()); // 52
/// ```
#[wasm_bindgen(js_name = "createBlackjackDeck")]
pub fn create_blackjack_deck(config: &WasmBlackjackDeckConfig) -> Result<WasmDeck, JsValue> {
    let native_config = config.to_native();
    native_config
        .validate()
        .map_err(|e| JsValue::from_str(&format!("Invalid config: {}", e)))?;

    let cards = create_blackjack_cards(&native_config);
    Ok(WasmDeck::from_cards_internal(cards))
}

/// Get the card indices for a Blackjack deck configuration.
///
/// Returns an array of card indices (1-52 repeated for each deck).
///
/// # Arguments
/// * `config` - The deck configuration
///
/// # Example
/// ```typescript
/// const config = WasmBlackjackDeckConfig.singleDeck();
/// const indices = getBlackjackCardIndices(config);
/// // indices = [1, 2, 3, ..., 52]
/// ```
#[wasm_bindgen(js_name = "getBlackjackCardIndices")]
pub fn get_blackjack_card_indices(config: &WasmBlackjackDeckConfig) -> Vec<u32> {
    let native_config = config.to_native();
    create_blackjack_card_indices(&native_config)
        .into_iter()
        .map(|i| i as u32)
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    // ------------------------------------------------------------------------
    // Config Tests
    // ------------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn test_blackjack_config_single_deck() {
        let config = WasmBlackjackDeckConfig::single_deck();
        assert_eq!(config.num_decks, 1);
        assert_eq!(config.total_cards(), 52);
        assert!(config.validate().is_ok());
    }

    #[wasm_bindgen_test]
    fn test_blackjack_config_standard_shoe() {
        let config = WasmBlackjackDeckConfig::standard_shoe();
        assert_eq!(config.num_decks, 6);
        assert_eq!(config.total_cards(), 312);
        assert!(config.validate().is_ok());
    }

    #[wasm_bindgen_test]
    fn test_blackjack_config_eight_deck() {
        let config = WasmBlackjackDeckConfig::eight_deck_shoe();
        assert_eq!(config.num_decks, 8);
        assert_eq!(config.total_cards(), 416);
        assert!(config.validate().is_ok());
    }

    #[wasm_bindgen_test]
    fn test_blackjack_config_invalid() {
        let config = WasmBlackjackDeckConfig::new(0);
        assert!(config.validate().is_err());

        let config = WasmBlackjackDeckConfig::new(9);
        assert!(config.validate().is_err());
    }

    // ------------------------------------------------------------------------
    // Card Value Tests
    // ------------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn test_blackjack_card_value_numbers() {
        assert_eq!(blackjack_card_value(1).unwrap(), 2); // 2 of Clubs
        assert_eq!(blackjack_card_value(9).unwrap(), 10); // 10 of Clubs
    }

    #[wasm_bindgen_test]
    fn test_blackjack_card_value_faces() {
        assert_eq!(blackjack_card_value(10).unwrap(), 10); // J
        assert_eq!(blackjack_card_value(11).unwrap(), 10); // Q
        assert_eq!(blackjack_card_value(12).unwrap(), 10); // K
    }

    #[wasm_bindgen_test]
    fn test_blackjack_card_value_aces() {
        assert_eq!(blackjack_card_value(13).unwrap(), 11); // A of Clubs
        assert_eq!(blackjack_card_value(26).unwrap(), 11); // A of Diamonds
        assert_eq!(blackjack_card_value(52).unwrap(), 11); // A of Spades
    }

    #[wasm_bindgen_test]
    fn test_blackjack_card_value_invalid() {
        assert!(blackjack_card_value(0).is_err());
        assert!(blackjack_card_value(53).is_err());
    }

    #[wasm_bindgen_test]
    fn test_is_blackjack_ace_func() {
        assert!(is_blackjack_ace(13));
        assert!(is_blackjack_ace(26));
        assert!(is_blackjack_ace(39));
        assert!(is_blackjack_ace(52));
        assert!(!is_blackjack_ace(1));
        assert!(!is_blackjack_ace(10));
    }

    #[wasm_bindgen_test]
    fn test_is_blackjack_face_card_func() {
        assert!(is_blackjack_face_card(10)); // J
        assert!(is_blackjack_face_card(11)); // Q
        assert!(is_blackjack_face_card(12)); // K
        assert!(!is_blackjack_face_card(9)); // 10
        assert!(!is_blackjack_face_card(13)); // A
    }

    #[wasm_bindgen_test]
    fn test_is_blackjack_ten_value_func() {
        assert!(is_blackjack_ten_value(9)); // 10
        assert!(is_blackjack_ten_value(10)); // J
        assert!(is_blackjack_ten_value(11)); // Q
        assert!(is_blackjack_ten_value(12)); // K
        assert!(!is_blackjack_ten_value(8)); // 9
        assert!(!is_blackjack_ten_value(13)); // A
    }

    #[wasm_bindgen_test]
    fn test_format_blackjack_card_func() {
        assert_eq!(format_blackjack_card(1).unwrap(), "2♣");
        assert_eq!(format_blackjack_card(13).unwrap(), "A♣");
        assert_eq!(format_blackjack_card(52).unwrap(), "A♠");
    }

    // ------------------------------------------------------------------------
    // Hand Value Tests
    // ------------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn test_calculate_hand_value_hard() {
        let hand = calculate_blackjack_hand_value(&[6, 7]).unwrap(); // 7 + 8 = 15
        assert_eq!(hand.hard, 15);
        assert!(hand.soft.is_none());
        assert_eq!(hand.best(), 15);
    }

    #[wasm_bindgen_test]
    fn test_calculate_hand_value_soft() {
        let hand = calculate_blackjack_hand_value(&[13, 5]).unwrap(); // A + 6 = soft 17
        assert_eq!(hand.hard, 7);
        assert_eq!(hand.soft, Some(17));
        assert_eq!(hand.best(), 17);
        assert!(hand.is_soft());
    }

    #[wasm_bindgen_test]
    fn test_blackjack_best_value_func() {
        assert_eq!(blackjack_best_value(&[13, 9]).unwrap(), 21); // Blackjack
        assert_eq!(blackjack_best_value(&[6, 7]).unwrap(), 15); // 7 + 8
    }

    #[wasm_bindgen_test]
    fn test_is_blackjack_bust_func() {
        assert!(is_blackjack_bust(&[9, 10, 11])); // 10 + J + Q = 30
        assert!(!is_blackjack_bust(&[13, 9])); // 21
    }

    // ------------------------------------------------------------------------
    // Blackjack Detection Tests
    // ------------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn test_is_blackjack_true() {
        assert!(is_blackjack_wasm(&[13, 9])); // A + 10
        assert!(is_blackjack_wasm(&[13, 10])); // A + J
        assert!(is_blackjack_wasm(&[10, 26])); // J + A
    }

    #[wasm_bindgen_test]
    fn test_is_blackjack_false() {
        assert!(!is_blackjack_wasm(&[9, 10])); // 10 + J = 20
        assert!(!is_blackjack_wasm(&[13, 8])); // A + 9 = 20
        assert!(!is_blackjack_wasm(&[13, 5, 5])); // 3 cards
    }

    // ------------------------------------------------------------------------
    // Dealer Logic Tests
    // ------------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn test_should_dealer_hit_on_16() {
        assert!(should_dealer_hit_wasm(&[9, 5]).unwrap()); // 10 + 6 = 16
    }

    #[wasm_bindgen_test]
    fn test_should_dealer_stand_on_17() {
        assert!(!should_dealer_hit_wasm(&[9, 6]).unwrap()); // 10 + 7 = 17
    }

    #[wasm_bindgen_test]
    fn test_should_dealer_hit_soft17_variant() {
        // Standard: stand on soft 17
        assert!(!should_dealer_hit_wasm(&[13, 5]).unwrap()); // A + 6 = soft 17

        // Variant: hit on soft 17
        assert!(should_dealer_hit_soft17_wasm(&[13, 5]).unwrap());
    }

    // ------------------------------------------------------------------------
    // Winner Determination Tests
    // ------------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn test_determine_winner_player_wins() {
        let outcome = determine_blackjack_winner(&[9, 8], &[9, 6]).unwrap(); // 19 vs 17
        assert_eq!(outcome, WasmBlackjackOutcome::PlayerWins);
        assert!(is_blackjack_player_win(outcome));
    }

    #[wasm_bindgen_test]
    fn test_determine_winner_dealer_wins() {
        let outcome = determine_blackjack_winner(&[9, 5], &[9, 7]).unwrap(); // 16 vs 18
        assert_eq!(outcome, WasmBlackjackOutcome::DealerWins);
        assert!(!is_blackjack_player_win(outcome));
    }

    #[wasm_bindgen_test]
    fn test_determine_winner_push() {
        let outcome = determine_blackjack_winner(&[9, 7], &[9, 20]).unwrap(); // 18 vs 18
        assert_eq!(outcome, WasmBlackjackOutcome::Push);
        assert!(is_blackjack_push(outcome));
    }

    #[wasm_bindgen_test]
    fn test_determine_winner_player_blackjack() {
        let outcome = determine_blackjack_winner(&[13, 9], &[9, 7]).unwrap(); // BJ vs 18
        assert_eq!(outcome, WasmBlackjackOutcome::PlayerBlackjack);
        assert!(is_blackjack_player_win(outcome));
    }

    #[wasm_bindgen_test]
    fn test_determine_winner_dealer_blackjack() {
        let outcome = determine_blackjack_winner(&[9, 8], &[26, 10]).unwrap(); // 19 vs BJ
        assert_eq!(outcome, WasmBlackjackOutcome::DealerBlackjack);
        assert!(!is_blackjack_player_win(outcome));
    }

    #[wasm_bindgen_test]
    fn test_determine_winner_both_blackjack() {
        let outcome = determine_blackjack_winner(&[13, 9], &[26, 10]).unwrap(); // BJ vs BJ
        assert_eq!(outcome, WasmBlackjackOutcome::BothBlackjack);
        assert!(is_blackjack_push(outcome));
    }

    #[wasm_bindgen_test]
    fn test_determine_winner_player_busts() {
        let outcome = determine_blackjack_winner(&[9, 10, 11], &[9, 6]).unwrap(); // 30 vs 17
        assert_eq!(outcome, WasmBlackjackOutcome::PlayerBusts);
    }

    #[wasm_bindgen_test]
    fn test_determine_winner_dealer_busts() {
        let outcome = determine_blackjack_winner(&[9, 4], &[9, 10, 11]).unwrap(); // 15 vs 30
        assert_eq!(outcome, WasmBlackjackOutcome::DealerBusts);
        assert!(is_blackjack_player_win(outcome));
    }

    // ------------------------------------------------------------------------
    // Outcome Display Tests
    // ------------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn test_blackjack_outcome_display_text() {
        assert_eq!(
            blackjack_outcome_display(WasmBlackjackOutcome::PlayerBlackjack),
            "Blackjack! You win!"
        );
        assert_eq!(
            blackjack_outcome_display(WasmBlackjackOutcome::DealerWins),
            "Dealer wins"
        );
        assert_eq!(
            blackjack_outcome_display(WasmBlackjackOutcome::Push),
            "Push"
        );
    }

    // ------------------------------------------------------------------------
    // Payout Tests
    // ------------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn test_payout_blackjack() {
        // 3:2 payout: bet 100, win 150, get 250 total
        assert_eq!(
            calculate_blackjack_payout(100, WasmBlackjackOutcome::PlayerBlackjack),
            250
        );
    }

    #[wasm_bindgen_test]
    fn test_payout_win() {
        // 1:1 payout: bet 100, win 100, get 200 total
        assert_eq!(
            calculate_blackjack_payout(100, WasmBlackjackOutcome::PlayerWins),
            200
        );
        assert_eq!(
            calculate_blackjack_payout(100, WasmBlackjackOutcome::DealerBusts),
            200
        );
    }

    #[wasm_bindgen_test]
    fn test_payout_push() {
        // Bet returned
        assert_eq!(
            calculate_blackjack_payout(100, WasmBlackjackOutcome::Push),
            100
        );
        assert_eq!(
            calculate_blackjack_payout(100, WasmBlackjackOutcome::BothBlackjack),
            100
        );
    }

    #[wasm_bindgen_test]
    fn test_payout_loss() {
        // Lose bet
        assert_eq!(
            calculate_blackjack_payout(100, WasmBlackjackOutcome::DealerWins),
            0
        );
        assert_eq!(
            calculate_blackjack_payout(100, WasmBlackjackOutcome::DealerBlackjack),
            0
        );
        assert_eq!(
            calculate_blackjack_payout(100, WasmBlackjackOutcome::PlayerBusts),
            0
        );
    }

    // ------------------------------------------------------------------------
    // Deck Creation Tests
    // ------------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn test_create_blackjack_deck_single() {
        let config = WasmBlackjackDeckConfig::single_deck();
        let deck = create_blackjack_deck(&config).unwrap();
        assert_eq!(deck.len(), 52);
    }

    #[wasm_bindgen_test]
    fn test_create_blackjack_deck_shoe() {
        let config = WasmBlackjackDeckConfig::standard_shoe();
        let deck = create_blackjack_deck(&config).unwrap();
        assert_eq!(deck.len(), 312);
    }

    #[wasm_bindgen_test]
    fn test_get_blackjack_card_indices_single() {
        let config = WasmBlackjackDeckConfig::single_deck();
        let indices = get_blackjack_card_indices(&config);
        assert_eq!(indices.len(), 52);
        assert_eq!(indices[0], 1);
        assert_eq!(indices[51], 52);
    }

    #[wasm_bindgen_test]
    fn test_get_blackjack_card_indices_double() {
        let config = WasmBlackjackDeckConfig::double_deck();
        let indices = get_blackjack_card_indices(&config);
        assert_eq!(indices.len(), 104);
        // First deck
        assert_eq!(indices[0], 1);
        assert_eq!(indices[51], 52);
        // Second deck
        assert_eq!(indices[52], 1);
        assert_eq!(indices[103], 52);
    }
}
