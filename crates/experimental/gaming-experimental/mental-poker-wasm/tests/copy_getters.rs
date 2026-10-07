//! Exercise generated JavaScript accessors for scalar and nested fields.
use mental_poker_wasm::{
    WasmBlackjackDeckConfig, WasmCard, WasmCrossyDeckConfig, WasmHandValue, WasmPoint,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen(inline_js = r#"
function check(value, expected, message) {
    if (value !== expected) throw new Error(message);
}
export function checkGetters(blackjack, hand, crossy, card) {
    check(blackjack.num_decks, 2, 'deck getter');
    blackjack.num_decks = 6;
    check(blackjack.num_decks, 6, 'deck setter');
    check(hand.hard, 11, 'hand getter');
    check(hand.soft, 21, 'optional getter');
    check(hand.aces, 1, 'aces getter');
    hand.soft = undefined;
    check(hand.soft, undefined, 'optional setter');
    hand.hard = 12;
    check(hand.hard, 12, 'hand setter');
    check(crossy.survive_count, 20, 'survive getter');
    check(crossy.hit_count, 5, 'hit getter');
    crossy.hit_count = 6;
    check(crossy.hit_count, 6, 'hit setter');
    check(card.index, 1n, 'card getter');
    card.index = 2n;
    check(card.index, 2n, 'card setter');
    const point = card.point;
    point.x = 'changed';
    check(card.point.x, '0x1', 'nested getter clones');
    point.free();
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = checkGetters)]
    fn check_getters(
        blackjack: WasmBlackjackDeckConfig,
        hand: WasmHandValue,
        crossy: WasmCrossyDeckConfig,
        card: WasmCard,
    );
}

#[wasm_bindgen_test]
fn generated_scalar_and_nested_accessors() {
    check_getters(
        WasmBlackjackDeckConfig::new(2),
        WasmHandValue {
            hard: 11,
            soft: Some(21),
            aces: 1,
        },
        WasmCrossyDeckConfig::new(20, 5),
        WasmCard {
            index: 1,
            point: WasmPoint {
                x: "0x1".into(),
                y: "0x2".into(),
            },
        },
    );
}
