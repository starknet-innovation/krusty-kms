//! Nostr WASM SDK
//!
//! WebAssembly bindings for Nostr messaging utilities.

use wasm_bindgen::prelude::*;

/// Initialize the WASM module.
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Get the SDK version.
#[wasm_bindgen(js_name = "getVersion")]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
