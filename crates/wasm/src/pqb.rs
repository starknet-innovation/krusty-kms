//! Opaque PQB vault and transaction-bound request handles. See `docs/pqb-wasm.md`.
mod input;
mod output;
#[cfg(test)]
mod tests;

use input::{error, indices, network, transaction};
use krusty_kms::pqb::{PqbNetwork, PqbRequest, PqbSelection, PqbVault};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Rust-owned PQB secrets. Call `dispose()` (then `free()`) when finished.
#[wasm_bindgen]
pub struct WasmPqbVault {
    vault: Option<PqbVault>,
    network: PqbNetwork,
}

/// Validated Rust request. Public copies never control authorization.
#[wasm_bindgen]
pub struct WasmPqbRequest {
    request: Option<PqbRequest>,
}

#[wasm_bindgen]
impl WasmPqbVault {
    /// Derive from a BIP39 root. Each BIP85 child must back at most one vault.
    #[wasm_bindgen(js_name = fromMnemonic)]
    pub fn from_mnemonic(
        mnemonic: String,
        #[wasm_bindgen(unchecked_param_type = "number")] index: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] network_name: js_sys::JsString,
        passphrase: Option<String>,
    ) -> Result<WasmPqbVault, JsValue> {
        let (mnemonic, passphrase) = (Zeroizing::new(mnemonic), passphrase.map(Zeroizing::new));
        let network = network(&network_name)?;
        let index = crate::numeric_input::u32(index, "BIP85 index")?;
        let vault = PqbVault::from_mnemonic(
            &mnemonic,
            passphrase.as_deref().map_or("", String::as_str),
            index,
            network,
        )
        .map_err(error)?;
        Ok(Self {
            vault: Some(vault),
            network,
        })
    }

    /// Restore the 24-word BIP85 child phrase, never a wallet root phrase.
    #[wasm_bindgen(js_name = fromChildMnemonic)]
    pub fn from_child_mnemonic(
        words: String,
        #[wasm_bindgen(unchecked_param_type = "string")] network_name: js_sys::JsString,
    ) -> Result<WasmPqbVault, JsValue> {
        let words = Zeroizing::new(words);
        let network = network(&network_name)?;
        let vault = PqbVault::from_child_mnemonic(&words, network).map_err(error)?;
        Ok(Self {
            vault: Some(vault),
            network,
        })
    }

    /// Public script, commitments, key and menu points in canonical order.
    #[wasm_bindgen(js_name = publicMaterial, unchecked_return_type = "PqbPublicMaterial")]
    pub fn public_material(&self) -> Result<JsValue, JsValue> {
        output::public(&self.live()?.public_material().map_err(error)?)
    }

    /// Public deposit address/key bound to the vault's derivation network.
    #[wasm_bindgen(unchecked_return_type = "PqbDeposit")]
    pub fn deposit(&self) -> Result<JsValue, JsValue> {
        output::deposit(&self.live()?.deposit(self.network).map_err(error)?)
    }

    /// Full unsigned legacy transaction; no caller-supplied signing digest.
    #[wasm_bindgen(js_name = prepareDisclosure)]
    pub fn prepare_disclosure(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] transaction_hex: js_sys::JsString,
        #[wasm_bindgen(unchecked_param_type = "number")] input_index: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] expected_script_hash: js_sys::JsString,
        #[wasm_bindgen(unchecked_param_type = "number[]")] round0: JsValue,
        #[wasm_bindgen(unchecked_param_type = "number[]")] round1: JsValue,
        #[wasm_bindgen(unchecked_param_type = "number[]")] menus: JsValue,
    ) -> Result<WasmPqbRequest, JsValue> {
        let vault = self.live()?;
        let input_index = crate::numeric_input::u32(input_index, "input index")?;
        let hash = input::hash(&expected_script_hash)?;
        let selection = PqbSelection::new(indices(&round0)?, indices(&round1)?, indices(&menus)?)
            .map_err(error)?;
        let request = vault
            .prepare_disclosure(
                &transaction(&transaction_hex)?,
                input_index as usize,
                &hash,
                selection,
            )
            .map_err(error)?;
        Ok(WasmPqbRequest {
            request: Some(request),
        })
    }

    /// Journal the exact digest durably BEFORE calling; reject different digests forever.
    /// Returned JS disclosures cannot be reliably wiped. No puzzle/chain verification.
    #[wasm_bindgen(unchecked_return_type = "PqbDisclosure")]
    pub fn authorize(&self, request: &WasmPqbRequest) -> Result<JsValue, JsValue> {
        let disclosure = self.live()?.authorize(request.live()?).map_err(error)?;
        output::disclosure(&disclosure)
    }

    /// Sign only owned deposit inputs using strict Rust PSBT checks and SIGHASH_ALL.
    #[wasm_bindgen(js_name = signDepositPsbt)]
    pub fn sign_deposit_psbt(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] psbt_base64: js_sys::JsString,
        #[wasm_bindgen(unchecked_param_type = "number[]")] input_indices: JsValue,
    ) -> Result<String, JsValue> {
        let inputs = input::deposit_indices(&input_indices)?;
        self.live()?
            .sign_deposit_psbt(&input::psbt(&psbt_base64)?, &inputs)
            .map_err(error)
    }

    /// Drop and zeroize Rust secrets. Idempotent; further operations fail.
    pub fn dispose(&mut self) {
        self.vault.take();
    }
}
impl WasmPqbVault {
    fn live(&self) -> Result<&PqbVault, JsValue> {
        self.vault
            .as_ref()
            .ok_or_else(|| error("PQB vault disposed"))
    }
}
#[wasm_bindgen]
impl WasmPqbRequest {
    /// Public digest and sighashes; changing this copy cannot change the request.
    #[wasm_bindgen(unchecked_return_type = "PqbRequestInfo")]
    pub fn info(&self) -> Result<JsValue, JsValue> {
        output::request(self.live()?)
    }

    /// Drop the validated request. Idempotent; further operations fail.
    pub fn dispose(&mut self) {
        self.request.take();
    }
}
impl WasmPqbRequest {
    fn live(&self) -> Result<&PqbRequest, JsValue> {
        self.request
            .as_ref()
            .ok_or_else(|| error("PQB request disposed"))
    }
}
