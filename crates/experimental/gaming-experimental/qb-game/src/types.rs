//! Type definitions for the Computer Quarterback game.
//!
//! Defines offensive plays, defensive coverages, game phases, and state structures.

use serde::{Deserialize, Serialize};

// ============================================================================
// Offensive Plays
// ============================================================================

/// Offensive play types (12 plays).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OffensivePlay {
    // Short yardage (low risk, low reward)
    QbSneak,
    Dive,
    Draw,
    ScreenPass,
    // Medium yardage (medium risk, medium reward)
    Slant,
    OutRoute,
    InsideRun,
    PlayAction,
    // Deep yardage (high risk, high reward)
    PostRoute,
    FlyRoute,
    Sweep,
    HailMary,
}

impl OffensivePlay {
    /// All offensive plays.
    pub const ALL: [OffensivePlay; 12] = [
        Self::QbSneak,
        Self::Dive,
        Self::Draw,
        Self::ScreenPass,
        Self::Slant,
        Self::OutRoute,
        Self::InsideRun,
        Self::PlayAction,
        Self::PostRoute,
        Self::FlyRoute,
        Self::Sweep,
        Self::HailMary,
    ];

    /// Convert to index (0-11).
    pub fn to_index(self) -> usize {
        match self {
            Self::QbSneak => 0,
            Self::Dive => 1,
            Self::Draw => 2,
            Self::ScreenPass => 3,
            Self::Slant => 4,
            Self::OutRoute => 5,
            Self::InsideRun => 6,
            Self::PlayAction => 7,
            Self::PostRoute => 8,
            Self::FlyRoute => 9,
            Self::Sweep => 10,
            Self::HailMary => 11,
        }
    }

    /// Create from index (0-11).
    pub fn from_index(index: usize) -> Option<Self> {
        Self::ALL.get(index).copied()
    }

    /// Display name for the play.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::QbSneak => "QB Sneak",
            Self::Dive => "Dive",
            Self::Draw => "Draw",
            Self::ScreenPass => "Screen Pass",
            Self::Slant => "Slant",
            Self::OutRoute => "Out Route",
            Self::InsideRun => "Inside Run",
            Self::PlayAction => "Play Action",
            Self::PostRoute => "Post Route",
            Self::FlyRoute => "Fly Route",
            Self::Sweep => "Sweep",
            Self::HailMary => "Hail Mary",
        }
    }

    /// Category of the play.
    pub fn category(&self) -> PlayCategory {
        match self {
            Self::QbSneak | Self::Dive | Self::Draw | Self::ScreenPass => PlayCategory::Short,
            Self::Slant | Self::OutRoute | Self::InsideRun | Self::PlayAction => PlayCategory::Medium,
            Self::PostRoute | Self::FlyRoute | Self::Sweep | Self::HailMary => PlayCategory::Deep,
        }
    }
}

// ============================================================================
// Defensive Coverages
// ============================================================================

/// Defensive coverage types (10 coverages).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DefensiveCoverage {
    // Run defense
    GoalLine,
    Stack43,
    Blitz,
    // Zone defense
    Cover2,
    Cover3,
    Cover4,
    // Man defense
    ManUnder,
    PressMan,
    ZoneBlitz,
    // Special
    Prevent,
}

impl DefensiveCoverage {
    /// All defensive coverages.
    pub const ALL: [DefensiveCoverage; 10] = [
        Self::GoalLine,
        Self::Stack43,
        Self::Blitz,
        Self::Cover2,
        Self::Cover3,
        Self::Cover4,
        Self::ManUnder,
        Self::PressMan,
        Self::ZoneBlitz,
        Self::Prevent,
    ];

    /// Convert to index (0-9).
    pub fn to_index(self) -> usize {
        match self {
            Self::GoalLine => 0,
            Self::Stack43 => 1,
            Self::Blitz => 2,
            Self::Cover2 => 3,
            Self::Cover3 => 4,
            Self::Cover4 => 5,
            Self::ManUnder => 6,
            Self::PressMan => 7,
            Self::ZoneBlitz => 8,
            Self::Prevent => 9,
        }
    }

    /// Create from index (0-9).
    pub fn from_index(index: usize) -> Option<Self> {
        Self::ALL.get(index).copied()
    }

    /// Display name for the coverage.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::GoalLine => "Goal Line",
            Self::Stack43 => "4-3 Stack",
            Self::Blitz => "Blitz",
            Self::Cover2 => "Cover 2",
            Self::Cover3 => "Cover 3",
            Self::Cover4 => "Cover 4",
            Self::ManUnder => "Man Under",
            Self::PressMan => "Press Man",
            Self::ZoneBlitz => "Zone Blitz",
            Self::Prevent => "Prevent",
        }
    }

    /// Category of the coverage.
    pub fn category(&self) -> CoverageCategory {
        match self {
            Self::GoalLine | Self::Stack43 | Self::Blitz => CoverageCategory::RunDefense,
            Self::Cover2 | Self::Cover3 | Self::Cover4 => CoverageCategory::Zone,
            Self::ManUnder | Self::PressMan | Self::ZoneBlitz => CoverageCategory::Man,
            Self::Prevent => CoverageCategory::Special,
        }
    }
}

// ============================================================================
// Categories
// ============================================================================

/// Offensive play category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlayCategory {
    Short,
    Medium,
    Deep,
}

/// Defensive coverage category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageCategory {
    RunDefense,
    Zone,
    Man,
    Special,
}

// ============================================================================
// Game Phases
// ============================================================================

/// Game phase in the play cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GamePhase {
    /// Initial coin flip.
    CoinFlip,
    /// Play selection phase.
    PlaySelect,
    /// Both parties committing to plays.
    Commit,
    /// Revealing plays.
    Reveal,
    /// Offense claiming yards.
    Claim,
    /// Verification of claim.
    Verify,
    /// Result display.
    Result,
    /// Scoring (touchdown, field goal, etc.).
    Scoring,
    /// Game over.
    GameOver,
}

// ============================================================================
// Game State
// ============================================================================

/// Current down in a drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Down {
    First,
    Second,
    Third,
    Fourth,
}

impl Down {
    /// Convert to number (1-4).
    pub fn to_number(self) -> u8 {
        match self {
            Self::First => 1,
            Self::Second => 2,
            Self::Third => 3,
            Self::Fourth => 4,
        }
    }

    /// Create from number (1-4).
    pub fn from_number(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::First),
            2 => Some(Self::Second),
            3 => Some(Self::Third),
            4 => Some(Self::Fourth),
            _ => None,
        }
    }

    /// Next down, or None if turnover on downs.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::First => Some(Self::Second),
            Self::Second => Some(Self::Third),
            Self::Third => Some(Self::Fourth),
            Self::Fourth => None,
        }
    }
}

/// Which team has possession.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Possession {
    Home,
    Away,
}

impl Possession {
    /// Switch possession.
    pub fn switch(self) -> Self {
        match self {
            Self::Home => Self::Away,
            Self::Away => Self::Home,
        }
    }
}

/// Result of a single play.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayResult {
    /// The offensive play that was run.
    pub offense_play: OffensivePlay,
    /// The defensive coverage that was called.
    pub defense_coverage: DefensiveCoverage,
    /// True yards from the payoff matrix.
    pub true_yards: i32,
    /// Yards claimed by the offense.
    pub claimed_yards: i32,
    /// Lie magnitude (claimed - true).
    pub lie_magnitude: i32,
    /// Detection probability (0.0 - 1.0).
    pub detection_probability: f64,
    /// Whether the lie was caught.
    pub was_caught: bool,
    /// Final yards applied (claimed if not caught, penalty if caught).
    pub final_yards: i32,
    /// Penalty applied (if caught).
    pub penalty: Option<Penalty>,
}

/// Penalty for getting caught lying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Penalty {
    /// Yards lost.
    pub yard_loss: i32,
    /// Whether to lose the down.
    pub loss_of_down: bool,
    /// Whether this results in a turnover.
    pub turnover: bool,
}

/// State of the current drive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveState {
    /// Starting field position (0-100).
    pub starting_position: u8,
    /// Current field position (0-100, 0 = own goal line, 100 = opponent's goal line).
    pub current_position: u8,
    /// Current down.
    pub down: Down,
    /// Yards to go for first down.
    pub yards_to_go: u8,
    /// History of plays in this drive.
    pub play_history: Vec<PlayResult>,
}

impl DriveState {
    /// Create a new drive starting at a position.
    pub fn new(starting_position: u8) -> Self {
        Self {
            starting_position,
            current_position: starting_position,
            down: Down::First,
            yards_to_go: 10,
            play_history: Vec::new(),
        }
    }

    /// Check if this is a touchdown (reached opponent's goal line).
    pub fn is_touchdown(&self) -> bool {
        self.current_position >= 100
    }

    /// Check if this is a safety (pushed back into own end zone).
    pub fn is_safety(&self) -> bool {
        self.current_position == 0 && self.starting_position > 0
    }
}

/// Full game state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameState {
    /// Home team name.
    pub home_team: String,
    /// Away team name.
    pub away_team: String,
    /// Home team score.
    pub home_score: u8,
    /// Away team score.
    pub away_score: u8,
    /// Current quarter (1-4).
    pub quarter: u8,
    /// Current game phase.
    pub phase: GamePhase,
    /// Who has possession.
    pub possession: Possession,
    /// Current drive state.
    pub drive: DriveState,
    /// Session ID.
    pub session_id: String,
}

impl GameState {
    /// Create a new game.
    pub fn new(home_team: String, away_team: String, session_id: String) -> Self {
        Self {
            home_team,
            away_team,
            home_score: 0,
            away_score: 0,
            quarter: 1,
            phase: GamePhase::CoinFlip,
            possession: Possession::Home,
            drive: DriveState::new(25), // Start at 25 yard line
            session_id,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offensive_play_index_roundtrip() {
        for play in OffensivePlay::ALL {
            let index = play.to_index();
            let recovered = OffensivePlay::from_index(index).unwrap();
            assert_eq!(play, recovered);
        }
    }

    #[test]
    fn test_defensive_coverage_index_roundtrip() {
        for coverage in DefensiveCoverage::ALL {
            let index = coverage.to_index();
            let recovered = DefensiveCoverage::from_index(index).unwrap();
            assert_eq!(coverage, recovered);
        }
    }

    #[test]
    fn test_offensive_play_count() {
        assert_eq!(OffensivePlay::ALL.len(), 12);
    }

    #[test]
    fn test_defensive_coverage_count() {
        assert_eq!(DefensiveCoverage::ALL.len(), 10);
    }

    #[test]
    fn test_down_progression() {
        assert_eq!(Down::First.next(), Some(Down::Second));
        assert_eq!(Down::Second.next(), Some(Down::Third));
        assert_eq!(Down::Third.next(), Some(Down::Fourth));
        assert_eq!(Down::Fourth.next(), None);
    }

    #[test]
    fn test_down_number_roundtrip() {
        for n in 1..=4u8 {
            let down = Down::from_number(n).unwrap();
            assert_eq!(down.to_number(), n);
        }
    }

    #[test]
    fn test_possession_switch() {
        assert_eq!(Possession::Home.switch(), Possession::Away);
        assert_eq!(Possession::Away.switch(), Possession::Home);
    }

    #[test]
    fn test_drive_state_touchdown() {
        let mut drive = DriveState::new(25);
        assert!(!drive.is_touchdown());
        drive.current_position = 100;
        assert!(drive.is_touchdown());
    }

    #[test]
    fn test_play_categories() {
        assert_eq!(OffensivePlay::QbSneak.category(), PlayCategory::Short);
        assert_eq!(OffensivePlay::Slant.category(), PlayCategory::Medium);
        assert_eq!(OffensivePlay::HailMary.category(), PlayCategory::Deep);
    }

    #[test]
    fn test_coverage_categories() {
        assert_eq!(DefensiveCoverage::GoalLine.category(), CoverageCategory::RunDefense);
        assert_eq!(DefensiveCoverage::Cover2.category(), CoverageCategory::Zone);
        assert_eq!(DefensiveCoverage::ManUnder.category(), CoverageCategory::Man);
        assert_eq!(DefensiveCoverage::Prevent.category(), CoverageCategory::Special);
    }

    #[test]
    fn test_serialize_offensive_play() {
        let play = OffensivePlay::QbSneak;
        let json = serde_json::to_string(&play).unwrap();
        assert_eq!(json, "\"QB_SNEAK\"");
        let recovered: OffensivePlay = serde_json::from_str(&json).unwrap();
        assert_eq!(play, recovered);
    }

    #[test]
    fn test_serialize_defensive_coverage() {
        let coverage = DefensiveCoverage::Cover2;
        let json = serde_json::to_string(&coverage).unwrap();
        // SCREAMING_SNAKE_CASE converts Cover2 to COVER2 (no underscore before digits)
        assert_eq!(json, "\"COVER2\"");
        let recovered: DefensiveCoverage = serde_json::from_str(&json).unwrap();
        assert_eq!(coverage, recovered);
    }
}
