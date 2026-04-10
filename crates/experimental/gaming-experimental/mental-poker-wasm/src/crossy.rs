//! Crossy Road / Mission Uncrossable WASM bindings.
//!
//! WebAssembly bindings for the Crossy Road game primitives.

use crate::deck::WasmDeck;
use mental_poker::crossy::{
    calculate_multiplier, create_crossy_card_indices, get_card_index_for_lane,
    resolve_crossy_card_type, CrossyCardType, CrossyDeckConfig,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ============================================================================
// Deck Configuration
// ============================================================================

/// Configuration for a Crossy Road deck.
///
/// Determines the number of Survive and Hit cards in the deck.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmCrossyDeckConfig {
    /// Number of Survive cards (safe lanes)
    pub survive_count: u32,
    /// Number of Hit cards (obstacles)
    pub hit_count: u32,
}

#[wasm_bindgen]
impl WasmCrossyDeckConfig {
    /// Create a new deck configuration with custom counts.
    #[wasm_bindgen(constructor)]
    pub fn new(survive_count: u32, hit_count: u32) -> Self {
        Self {
            survive_count,
            hit_count,
        }
    }

    /// Easy difficulty: 20 survive, 5 hit (~80% survival rate per lane).
    #[wasm_bindgen]
    pub fn easy() -> Self {
        let config = CrossyDeckConfig::easy();
        Self {
            survive_count: config.survive_count,
            hit_count: config.hit_count,
        }
    }

    /// Medium difficulty: 15 survive, 10 hit (~60% survival rate per lane).
    #[wasm_bindgen]
    pub fn medium() -> Self {
        let config = CrossyDeckConfig::medium();
        Self {
            survive_count: config.survive_count,
            hit_count: config.hit_count,
        }
    }

    /// Hard difficulty: 10 survive, 15 hit (~40% survival rate per lane).
    #[wasm_bindgen]
    pub fn hard() -> Self {
        let config = CrossyDeckConfig::hard();
        Self {
            survive_count: config.survive_count,
            hit_count: config.hit_count,
        }
    }

    /// Daredevil difficulty: 5 survive, 20 hit (~20% survival rate per lane).
    #[wasm_bindgen]
    pub fn daredevil() -> Self {
        let config = CrossyDeckConfig::daredevil();
        Self {
            survive_count: config.survive_count,
            hit_count: config.hit_count,
        }
    }

    /// Get the total number of cards in the deck.
    #[wasm_bindgen(js_name = "totalCards")]
    pub fn total_cards(&self) -> u32 {
        self.survive_count + self.hit_count
    }

    /// Get the survival probability per lane selection.
    #[wasm_bindgen(js_name = "survivalRate")]
    pub fn survival_rate(&self) -> f64 {
        let total = self.total_cards();
        if total == 0 {
            return 0.0;
        }
        self.survive_count as f64 / total as f64
    }

    /// Convert to native CrossyDeckConfig.
    fn to_native(&self) -> CrossyDeckConfig {
        CrossyDeckConfig::new(self.survive_count, self.hit_count)
    }
}

// ============================================================================
// Deck Creation
// ============================================================================

/// Create a Crossy Road deck with the specified configuration.
///
/// Returns a WasmDeck with cards ordered: all Survive cards first, then all Hit cards.
/// The deck should be shuffled before use.
///
/// # Arguments
/// * `config` - The deck configuration specifying survive/hit card counts
///
/// # Example
/// ```typescript
/// const config = WasmCrossyDeckConfig.easy();
/// const deck = createCrossyDeck(config);
/// console.log(deck.length()); // 25
/// ```
#[wasm_bindgen(js_name = "createCrossyDeck")]
pub fn create_crossy_deck(config: &WasmCrossyDeckConfig) -> WasmDeck {
    // Create a deck with just 2 card types (index 1 and 2)
    // The deck module's create_deck creates sequential cards 1..=n
    // We need to create cards with our specific indices
    let native_config = config.to_native();
    let indices = create_crossy_card_indices(&native_config);

    // Create cards for each index
    use mental_poker::types::Card;
    let cards: Vec<Card> = indices.into_iter().map(Card::from_index).collect();

    // Create a WasmDeck from these cards
    WasmDeck::from_cards_internal(cards)
}

/// Get the card indices for a Crossy Road deck configuration.
///
/// Returns an array of card indices (1 for Survive, 2 for Hit)
/// in the order they should appear in the unshuffled deck.
///
/// # Arguments
/// * `config` - The deck configuration
///
/// # Example
/// ```typescript
/// const config = WasmCrossyDeckConfig.easy();
/// const indices = getCrossyCardIndices(config);
/// // indices = [1, 1, 1, ..., 2, 2, 2, 2, 2] (20 ones, 5 twos)
/// ```
#[wasm_bindgen(js_name = "getCrossyCardIndices")]
pub fn get_crossy_card_indices(config: &WasmCrossyDeckConfig) -> Vec<u32> {
    let native_config = config.to_native();
    create_crossy_card_indices(&native_config)
        .into_iter()
        .map(|i| i as u32)
        .collect()
}

// ============================================================================
// Card Type Resolution
// ============================================================================

/// Resolve a card index to its Crossy card type.
///
/// # Arguments
/// * `card_index` - The resolved card index (1 = Survive, 2 = Hit)
///
/// # Returns
/// * "survive" if the card is safe
/// * "hit" if the card is an obstacle
/// * Error if the index is not 1 or 2
///
/// # Example
/// ```typescript
/// const cardType = resolveCrossyCardType(1);
/// console.log(cardType); // "survive"
///
/// const hitType = resolveCrossyCardType(2);
/// console.log(hitType); // "hit"
/// ```
#[wasm_bindgen(js_name = "resolveCrossyCardType")]
pub fn resolve_crossy_card_type_wasm(card_index: u32) -> Result<String, JsValue> {
    let card_type = resolve_crossy_card_type(card_index as u64)
        .map_err(|e| JsValue::from_str(&format!("Invalid card index: {}", e)))?;

    Ok(match card_type {
        CrossyCardType::Survive => "survive".to_string(),
        CrossyCardType::Hit => "hit".to_string(),
    })
}

/// Check if a card index represents a Survive card.
///
/// # Arguments
/// * `card_index` - The resolved card index
///
/// # Returns
/// true if card_index == 1 (Survive), false otherwise
#[wasm_bindgen(js_name = "isCrossySurviveCard")]
pub fn is_crossy_survive_card(card_index: u32) -> bool {
    card_index == CrossyCardType::Survive as u32
}

/// Check if a card index represents a Hit card.
///
/// # Arguments
/// * `card_index` - The resolved card index
///
/// # Returns
/// true if card_index == 2 (Hit), false otherwise
#[wasm_bindgen(js_name = "isCrossyHitCard")]
pub fn is_crossy_hit_card(card_index: u32) -> bool {
    card_index == CrossyCardType::Hit as u32
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
/// * `row` - The current row (0-indexed)
/// * `lane` - The selected lane (1-indexed, typically 1-5)
/// * `lanes_per_row` - Number of lanes per row (typically 5)
///
/// # Returns
/// The deck index for the specified lane/row combination.
///
/// # Example
/// ```typescript
/// // Row 0, Lane 1 -> index 0
/// getCrossyCardIndexForLane(0, 1, 5); // returns 0
///
/// // Row 0, Lane 5 -> index 4
/// getCrossyCardIndexForLane(0, 5, 5); // returns 4
///
/// // Row 1, Lane 3 -> index 7
/// getCrossyCardIndexForLane(1, 3, 5); // returns 7
/// ```
#[wasm_bindgen(js_name = "getCrossyCardIndexForLane")]
pub fn get_crossy_card_index_for_lane(row: u32, lane: u32, lanes_per_row: u32) -> u32 {
    get_card_index_for_lane(row, lane, lanes_per_row) as u32
}

/// Calculate the multiplier for a given number of completed rows.
///
/// # Arguments
/// * `rows_completed` - Number of rows successfully crossed
/// * `base_multiplier` - Starting multiplier (typically 1.0)
/// * `increment` - Multiplier increase per row (e.g., 0.25)
///
/// # Returns
/// The calculated multiplier for the given progress.
///
/// # Example
/// ```typescript
/// calculateCrossyMultiplier(0, 1.0, 0.25); // 1.0
/// calculateCrossyMultiplier(1, 1.0, 0.25); // 1.25
/// calculateCrossyMultiplier(4, 1.0, 0.25); // 2.0
/// ```
#[wasm_bindgen(js_name = "calculateCrossyMultiplier")]
pub fn calculate_crossy_multiplier(
    rows_completed: u32,
    base_multiplier: f64,
    increment: f64,
) -> f64 {
    calculate_multiplier(rows_completed, base_multiplier, increment)
}

/// Get the recommended number of rows for a deck configuration.
///
/// Based on total cards and lanes per row.
///
/// # Arguments
/// * `config` - The deck configuration
/// * `lanes_per_row` - Number of lanes per row (typically 5)
///
/// # Returns
/// The number of rows that can be played with the deck.
#[wasm_bindgen(js_name = "getCrossyTotalRows")]
pub fn get_crossy_total_rows(config: &WasmCrossyDeckConfig, lanes_per_row: u32) -> u32 {
    config.total_cards() / lanes_per_row
}

// ============================================================================
// Difficulty Helpers
// ============================================================================

/// Get the difficulty name for a configuration.
///
/// Matches against standard difficulty presets.
///
/// # Returns
/// "easy", "medium", "hard", "daredevil", or "custom"
#[wasm_bindgen(js_name = "getCrossyDifficultyName")]
pub fn get_crossy_difficulty_name(config: &WasmCrossyDeckConfig) -> String {
    match (config.survive_count, config.hit_count) {
        (20, 5) => "easy".to_string(),
        (15, 10) => "medium".to_string(),
        (10, 15) => "hard".to_string(),
        (5, 20) => "daredevil".to_string(),
        _ => "custom".to_string(),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_crossy_config_easy() {
        let config = WasmCrossyDeckConfig::easy();
        assert_eq!(config.survive_count, 20);
        assert_eq!(config.hit_count, 5);
        assert_eq!(config.total_cards(), 25);
    }

    #[wasm_bindgen_test]
    fn test_crossy_config_medium() {
        let config = WasmCrossyDeckConfig::medium();
        assert_eq!(config.survive_count, 15);
        assert_eq!(config.hit_count, 10);
        assert_eq!(config.total_cards(), 25);
    }

    #[wasm_bindgen_test]
    fn test_crossy_config_hard() {
        let config = WasmCrossyDeckConfig::hard();
        assert_eq!(config.survive_count, 10);
        assert_eq!(config.hit_count, 15);
        assert_eq!(config.total_cards(), 25);
    }

    #[wasm_bindgen_test]
    fn test_crossy_config_daredevil() {
        let config = WasmCrossyDeckConfig::daredevil();
        assert_eq!(config.survive_count, 5);
        assert_eq!(config.hit_count, 20);
        assert_eq!(config.total_cards(), 25);
    }

    #[wasm_bindgen_test]
    fn test_crossy_survival_rate() {
        let easy = WasmCrossyDeckConfig::easy();
        assert!((easy.survival_rate() - 0.8).abs() < 0.001);

        let daredevil = WasmCrossyDeckConfig::daredevil();
        assert!((daredevil.survival_rate() - 0.2).abs() < 0.001);
    }

    #[wasm_bindgen_test]
    fn test_crossy_card_indices() {
        let config = WasmCrossyDeckConfig::easy();
        let indices = get_crossy_card_indices(&config);

        assert_eq!(indices.len(), 25);
        let survive_count = indices.iter().filter(|&&i| i == 1).count();
        let hit_count = indices.iter().filter(|&&i| i == 2).count();
        assert_eq!(survive_count, 20);
        assert_eq!(hit_count, 5);
    }

    #[wasm_bindgen_test]
    fn test_crossy_create_deck() {
        let config = WasmCrossyDeckConfig::easy();
        let deck = create_crossy_deck(&config);
        assert_eq!(deck.len(), 25);
    }

    #[wasm_bindgen_test]
    fn test_crossy_resolve_survive() {
        let result = resolve_crossy_card_type_wasm(1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "survive");
    }

    #[wasm_bindgen_test]
    fn test_crossy_resolve_hit() {
        let result = resolve_crossy_card_type_wasm(2);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hit");
    }

    #[wasm_bindgen_test]
    fn test_crossy_is_survive_card() {
        assert!(is_crossy_survive_card(1));
        assert!(!is_crossy_survive_card(2));
        assert!(!is_crossy_survive_card(0));
    }

    #[wasm_bindgen_test]
    fn test_crossy_is_hit_card() {
        assert!(is_crossy_hit_card(2));
        assert!(!is_crossy_hit_card(1));
        assert!(!is_crossy_hit_card(0));
    }

    #[wasm_bindgen_test]
    fn test_crossy_lane_index() {
        assert_eq!(get_crossy_card_index_for_lane(0, 1, 5), 0);
        assert_eq!(get_crossy_card_index_for_lane(0, 5, 5), 4);
        assert_eq!(get_crossy_card_index_for_lane(1, 3, 5), 7);
    }

    #[wasm_bindgen_test]
    fn test_crossy_multiplier() {
        assert_eq!(calculate_crossy_multiplier(0, 1.0, 0.25), 1.0);
        assert_eq!(calculate_crossy_multiplier(1, 1.0, 0.25), 1.25);
        assert_eq!(calculate_crossy_multiplier(4, 1.0, 0.25), 2.0);
    }

    #[wasm_bindgen_test]
    fn test_crossy_total_rows() {
        let config = WasmCrossyDeckConfig::easy();
        assert_eq!(get_crossy_total_rows(&config, 5), 5);
    }

    #[wasm_bindgen_test]
    fn test_crossy_difficulty_name() {
        assert_eq!(
            get_crossy_difficulty_name(&WasmCrossyDeckConfig::easy()),
            "easy"
        );
        assert_eq!(
            get_crossy_difficulty_name(&WasmCrossyDeckConfig::medium()),
            "medium"
        );
        assert_eq!(
            get_crossy_difficulty_name(&WasmCrossyDeckConfig::hard()),
            "hard"
        );
        assert_eq!(
            get_crossy_difficulty_name(&WasmCrossyDeckConfig::daredevil()),
            "daredevil"
        );
        assert_eq!(
            get_crossy_difficulty_name(&WasmCrossyDeckConfig::new(10, 10)),
            "custom"
        );
    }
}
