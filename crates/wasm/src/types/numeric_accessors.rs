//! Validated JavaScript accessors for numeric account-state fields.

use super::WasmAccountState;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
impl WasmAccountState {
    #[wasm_bindgen(getter = nonce)]
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    #[wasm_bindgen(setter = nonce)]
    pub fn set_nonce(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "bigint")] nonce: JsValue,
    ) -> Result<(), JsValue> {
        self.nonce = crate::numeric_input::u64(nonce, "transaction nonce")?;
        Ok(())
    }
}
