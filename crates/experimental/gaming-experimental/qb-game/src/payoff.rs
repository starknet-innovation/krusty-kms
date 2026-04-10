//! Payoff matrix for the Computer Quarterback game.
//!
//! Defines the expected yards for each offensive play vs defensive coverage matchup.

use crate::types::{DefensiveCoverage, OffensivePlay};

/// Get the yard outcome for a play matchup.
///
/// Returns the expected yards gained for the given offensive play
/// against the given defensive coverage.
pub fn get_yards(offense: OffensivePlay, defense: DefensiveCoverage) -> i32 {
    PAYOFF_MATRIX[offense.to_index()][defense.to_index()]
}

/// Get the maximum possible yards for a given offensive play.
///
/// This is used to cap the claimed yards.
pub fn max_yards_for_play(offense: OffensivePlay) -> i32 {
    PAYOFF_MATRIX[offense.to_index()]
        .iter()
        .copied()
        .max()
        .unwrap_or(0)
}

/// Get the minimum possible yards for a given offensive play.
pub fn min_yards_for_play(offense: OffensivePlay) -> i32 {
    PAYOFF_MATRIX[offense.to_index()]
        .iter()
        .copied()
        .min()
        .unwrap_or(0)
}

/// 12x10 payoff matrix: [offensive_play][defensive_coverage] -> yards
///
/// Row indices (offense):
///   0: QbSneak, 1: Dive, 2: Draw, 3: ScreenPass
///   4: Slant, 5: OutRoute, 6: InsideRun, 7: PlayAction
///   8: PostRoute, 9: FlyRoute, 10: Sweep, 11: HailMary
///
/// Column indices (defense):
///   0: GoalLine, 1: Stack43, 2: Blitz, 3: Cover2, 4: Cover3
///   5: Cover4, 6: ManUnder, 7: PressMan, 8: ZoneBlitz, 9: Prevent
///
/// Design principles:
/// - BLITZ crushes passes (sacks: -1 to -5) but gives up big runs
/// - Stacked boxes stop runs (TFL: -1) but vulnerable to passes
/// - PREVENT stops deep passes but gives up short gains
/// - Every play has risk - no guaranteed positive yards
/// - Rock-paper-scissors dynamics with no dominant strategy
const PAYOFF_MATRIX: [[i32; 10]; 12] = [
    // QbSneak: Short yardage, consistent (conservative)
    [1, 1, 4, 2, 2, 2, 2, 2, 3, 3],
    // Dive: Inside run, stopped at goal line
    [0, 1, 6, 3, 3, 3, 3, 3, 4, 4],
    // Draw: Delayed handoff, good vs blitz
    [2, 2, 7, 4, 4, 4, 4, 4, 2, 5],
    // ScreenPass: Short pass, SACKED by blitz/press/zone blitz
    [1, 3, -2, 3, 4, 4, 2, -1, -1, 6],
    // Slant: Quick pass, sacked by blitz
    [3, 4, -1, 5, 6, 7, 4, 2, 1, 8],
    // OutRoute: Sideline pass, sacked by blitz
    [4, 6, -1, 6, 5, 8, 5, 3, 2, 9],
    // InsideRun: Standard run, TFL vs stacked boxes
    [-1, -1, 8, 4, 4, 4, 4, 4, 5, 5],
    // PlayAction: Fake run then pass, BIG SACK vs blitz/zone blitz
    [5, 7, -4, 8, 10, 12, 7, 4, -2, 14],
    // PostRoute: Deep middle, sacked by blitz
    [6, 8, -2, 10, 7, 9, 14, 10, 3, 15],
    // FlyRoute: Go route, sacked by blitz
    [8, 10, -3, 7, 9, 5, 18, 15, 5, 10],
    // Sweep: Outside run, TFL at goal line
    [-1, 1, 10, 3, 3, 3, 3, 3, 6, 6],
    // HailMary: Desperation, BIG SACK vs blitz, INTERCEPTED vs prevent
    [12, 15, -5, 5, 8, 6, 22, 18, 8, -1],
];

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matrix_dimensions() {
        // 12 offensive plays
        assert_eq!(PAYOFF_MATRIX.len(), 12);
        // 10 defensive coverages each
        for row in &PAYOFF_MATRIX {
            assert_eq!(row.len(), 10);
        }
    }

    #[test]
    fn test_blitz_crushes_passes() {
        // Blitz should give negative yards for pass plays (sacks)
        let blitz = DefensiveCoverage::Blitz;

        // Screen pass vs blitz = -2 yards (sack)
        assert_eq!(get_yards(OffensivePlay::ScreenPass, blitz), -2);

        // Play action vs blitz = -4 yards (big sack)
        assert_eq!(get_yards(OffensivePlay::PlayAction, blitz), -4);

        // Hail Mary vs blitz = -5 yards (huge sack)
        assert_eq!(get_yards(OffensivePlay::HailMary, blitz), -5);

        // But sweep vs blitz = 10 yards (big gain, runs beat blitz)
        assert_eq!(get_yards(OffensivePlay::Sweep, blitz), 10);
    }

    #[test]
    fn test_prevent_stops_deep() {
        // Prevent should limit deep plays but give up short ones
        let prevent = DefensiveCoverage::Prevent;

        // Hail Mary vs prevent = -1 yard (interception!)
        assert_eq!(get_yards(OffensivePlay::HailMary, prevent), -1);

        // But slant vs prevent = 8 yards (easy yards underneath)
        assert_eq!(get_yards(OffensivePlay::Slant, prevent), 8);
    }

    #[test]
    fn test_stacked_boxes_stop_runs() {
        let goal_line = DefensiveCoverage::GoalLine;
        let stack43 = DefensiveCoverage::Stack43;

        // Inside run vs goal line = -1 yards (TFL)
        assert_eq!(get_yards(OffensivePlay::InsideRun, goal_line), -1);

        // Inside run vs stack = -1 yards (TFL)
        assert_eq!(get_yards(OffensivePlay::InsideRun, stack43), -1);

        // Sweep vs goal line = -1 yards (TFL)
        assert_eq!(get_yards(OffensivePlay::Sweep, goal_line), -1);

        // QB sneak vs goal line = 1 yard (still works)
        assert_eq!(get_yards(OffensivePlay::QbSneak, goal_line), 1);
    }

    #[test]
    fn test_man_coverage_vulnerable_to_deep() {
        let man_under = DefensiveCoverage::ManUnder;

        // Fly route vs man = 18 yards (huge gain)
        assert_eq!(get_yards(OffensivePlay::FlyRoute, man_under), 18);

        // Hail Mary vs man = 22 yards (massive)
        assert_eq!(get_yards(OffensivePlay::HailMary, man_under), 22);
    }

    #[test]
    fn test_max_yards_for_play() {
        // Hail Mary has highest potential (22 vs man)
        assert_eq!(max_yards_for_play(OffensivePlay::HailMary), 22);

        // QB Sneak has low max (4 vs blitz)
        assert_eq!(max_yards_for_play(OffensivePlay::QbSneak), 4);
    }

    #[test]
    fn test_min_yards_for_play() {
        // Hail Mary has very negative minimum (-5 vs blitz)
        assert_eq!(min_yards_for_play(OffensivePlay::HailMary), -5);

        // Play action also very risky (-4 vs blitz)
        assert_eq!(min_yards_for_play(OffensivePlay::PlayAction), -4);

        // Inside run has -1 minimum (TFL vs stacked boxes)
        assert_eq!(min_yards_for_play(OffensivePlay::InsideRun), -1);
    }

    #[test]
    fn test_all_matchups_accessible() {
        // Every combination should return a valid value
        for offense in OffensivePlay::ALL {
            for defense in DefensiveCoverage::ALL {
                let yards = get_yards(offense, defense);
                // Yards should be in reasonable range
                assert!(
                    (-10..=50).contains(&yards),
                    "Yards out of range for {:?} vs {:?}: {}",
                    offense,
                    defense,
                    yards
                );
            }
        }
    }

    #[test]
    fn test_no_dominant_strategy() {
        // For each offensive play, there should be some good and some bad matchups
        for offense in OffensivePlay::ALL {
            let max = max_yards_for_play(offense);
            let min = min_yards_for_play(offense);
            let range = max - min;

            // Each play should have at least 3 yard range
            assert!(
                range >= 3,
                "{:?} has too narrow range: {} to {}",
                offense,
                min,
                max
            );
        }
    }
}
