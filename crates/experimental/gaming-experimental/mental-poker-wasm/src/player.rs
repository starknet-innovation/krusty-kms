//! Player management for mental poker.
//!
//! Handles key generation, proof creation, and player state.

use crate::types::{WasmDLEqualityProof, WasmKeyOwnershipProof, WasmPublicKey};
use mental_poker::MentalPokerProtocol;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// A player in a mental poker game.
///
/// Contains the player's keypair and can generate proofs.
#[wasm_bindgen]
pub struct WasmPlayer {
    /// Secret key (hex string)
    secret_key: String,
    /// Public key X coordinate
    public_key_x: String,
    /// Public key Y coordinate
    public_key_y: String,
}

#[wasm_bindgen]
impl WasmPlayer {
    /// Get the public key.
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> WasmPublicKey {
        WasmPublicKey {
            x: self.public_key_x.clone(),
            y: self.public_key_y.clone(),
        }
    }

    /// Get the public key as concatenated hex "0x{x}{y}".
    #[wasm_bindgen(js_name = "publicKeyHex")]
    pub fn public_key_hex(&self) -> String {
        let pk = self.public_key();
        pk.to_hex()
    }

    /// Generate a proof of key ownership.
    ///
    /// The context should be unique per player (e.g., player ID or session).
    #[wasm_bindgen(js_name = "proveKeyOwnership")]
    pub fn prove_key_ownership(&self, context: &str) -> Result<WasmKeyOwnershipProof, JsValue> {
        use mental_poker::types::{PublicKey, SecretKey};
        use starknet_types_core::curve::ProjectivePoint;
        use starknet_types_core::felt::Felt;

        let sk_felt = Felt::from_hex(&self.secret_key)
            .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {e}")))?;
        let pk_x = Felt::from_hex(&self.public_key_x)
            .map_err(|e| JsValue::from_str(&format!("Invalid public key x: {e}")))?;
        let pk_y = Felt::from_hex(&self.public_key_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid public key y: {e}")))?;

        let sk = SecretKey::new(sk_felt);
        let pk = PublicKey::new(
            ProjectivePoint::from_affine(pk_x, pk_y)
                .map_err(|e| JsValue::from_str(&format!("Invalid public key point: {e:?}")))?,
        );

        let proof = MentalPokerProtocol::prove_key_ownership(&pk, &sk, context.as_bytes())
            .map_err(|e| JsValue::from_str(&format!("Failed to generate proof: {e}")))?;

        Ok(proof.into())
    }

    /// Compute a reveal token for a masked card.
    ///
    /// Returns the token and a proof of correctness.
    #[wasm_bindgen(js_name = "computeRevealToken")]
    pub fn compute_reveal_token(
        &self,
        masked_c0_x: &str,
        masked_c0_y: &str,
        masked_c1_x: &str,
        masked_c1_y: &str,
    ) -> Result<WasmRevealTokenResult, JsValue> {
        use mental_poker::types::{MaskedCard, PublicKey, SecretKey};
        use starknet_types_core::curve::ProjectivePoint;
        use starknet_types_core::felt::Felt;

        // Parse inputs
        let sk_felt = Felt::from_hex(&self.secret_key)
            .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {e}")))?;
        let pk_x = Felt::from_hex(&self.public_key_x)
            .map_err(|e| JsValue::from_str(&format!("Invalid public key x: {e}")))?;
        let pk_y = Felt::from_hex(&self.public_key_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid public key y: {e}")))?;

        let c0_x = Felt::from_hex(masked_c0_x)
            .map_err(|e| JsValue::from_str(&format!("Invalid c0 x: {e}")))?;
        let c0_y = Felt::from_hex(masked_c0_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid c0 y: {e}")))?;
        let c1_x = Felt::from_hex(masked_c1_x)
            .map_err(|e| JsValue::from_str(&format!("Invalid c1 x: {e}")))?;
        let c1_y = Felt::from_hex(masked_c1_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid c1 y: {e}")))?;

        let sk = SecretKey::new(sk_felt);
        let pk = PublicKey::new(
            ProjectivePoint::from_affine(pk_x, pk_y)
                .map_err(|e| JsValue::from_str(&format!("Invalid public key: {e:?}")))?,
        );
        let c0 = ProjectivePoint::from_affine(c0_x, c0_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid c0: {e:?}")))?;
        let c1 = ProjectivePoint::from_affine(c1_x, c1_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid c1: {e:?}")))?;

        let masked = MaskedCard::new(c0, c1);

        let (token, proof) = MentalPokerProtocol::compute_reveal_token(&masked, &sk, &pk)
            .map_err(|e| JsValue::from_str(&format!("Failed to compute reveal token: {e}")))?;

        let token_affine = token
            .point
            .to_affine()
            .map_err(|_| JsValue::from_str("Invalid token point"))?;

        Ok(WasmRevealTokenResult {
            token_x: format!("{:#x}", token_affine.x()),
            token_y: format!("{:#x}", token_affine.y()),
            proof: proof.into(),
        })
    }
}

/// Result of computing a reveal token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmRevealTokenResult {
    pub token_x: String,
    pub token_y: String,
    pub proof: WasmDLEqualityProof,
}

/// Result of key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmKeypairResult {
    /// Secret key (hex string) - keep this private!
    pub secret_key: String,
    /// Public key
    pub public_key: WasmPublicKey,
    /// Pre-computed key ownership proof (can be shared)
    pub key_ownership_proof: WasmKeyOwnershipProof,
}

/// Generate a new keypair for mental poker.
///
/// Returns a keypair with a pre-computed key ownership proof.
#[wasm_bindgen(js_name = "generateKeypair")]
pub fn generate_keypair(context: &str) -> Result<WasmKeypairResult, JsValue> {
    let (pk, sk) = MentalPokerProtocol::player_keygen();

    let pk_affine = pk
        .point
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid public key point"))?;

    let proof = MentalPokerProtocol::prove_key_ownership(&pk, &sk, context.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("Failed to generate proof: {e}")))?;

    let public_key = WasmPublicKey {
        x: format!("{:#x}", pk_affine.x()),
        y: format!("{:#x}", pk_affine.y()),
    };

    Ok(WasmKeypairResult {
        secret_key: format!("{:#x}", sk.scalar),
        public_key,
        key_ownership_proof: proof.into(),
    })
}

/// Create a WasmPlayer from an existing secret key.
#[wasm_bindgen(js_name = "playerFromSecretKey")]
pub fn player_from_secret_key(secret_key: &str) -> Result<WasmPlayer, JsValue> {
    use mental_poker::types::SecretKey;
    use starknet_types_core::felt::Felt;

    let sk_felt = Felt::from_hex(secret_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {e}")))?;

    let sk = SecretKey::new(sk_felt);
    let pk = sk.public_key();

    let pk_affine = pk
        .point
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid public key point"))?;

    Ok(WasmPlayer {
        secret_key: format!("{:#x}", sk.scalar),
        public_key_x: format!("{:#x}", pk_affine.x()),
        public_key_y: format!("{:#x}", pk_affine.y()),
    })
}

/// Input for aggregate key computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct WasmAggregateKeyInput {
    pub public_key: WasmPublicKey,
    pub proof: WasmKeyOwnershipProof,
    pub context: String,
}

#[wasm_bindgen]
impl WasmAggregateKeyInput {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: WasmPublicKey, proof: WasmKeyOwnershipProof, context: String) -> Self {
        Self {
            public_key,
            proof,
            context,
        }
    }
}

/// Verify a key ownership proof.
#[wasm_bindgen(js_name = "verifyKeyOwnership")]
pub fn verify_key_ownership(
    public_key: &WasmPublicKey,
    proof: &WasmKeyOwnershipProof,
    context: &str,
) -> Result<bool, JsValue> {
    use mental_poker::types::PublicKey;
    use starknet_types_core::curve::ProjectivePoint;
    use starknet_types_core::felt::Felt;

    let pk_x = Felt::from_hex(&public_key.x)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key x: {e}")))?;
    let pk_y = Felt::from_hex(&public_key.y)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key y: {e}")))?;

    let pk = PublicKey::new(
        ProjectivePoint::from_affine(pk_x, pk_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid public key: {e:?}")))?,
    );

    let native_proof: mental_poker::types::KeyOwnershipProof = proof.clone().into();

    MentalPokerProtocol::verify_key_ownership(&pk, &native_proof, context.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("Verification failed: {e}")))
}

/// Compute the aggregate public key from all players.
///
/// Verifies all key ownership proofs before aggregating.
#[wasm_bindgen(js_name = "aggregatePublicKeys")]
pub fn aggregate_public_keys(inputs: Vec<WasmAggregateKeyInput>) -> Result<WasmPublicKey, JsValue> {
    use mental_poker::types::{KeyOwnershipProof, PublicKey};
    use starknet_types_core::curve::ProjectivePoint;
    use starknet_types_core::felt::Felt;

    let mut keys_with_proofs: Vec<(PublicKey, KeyOwnershipProof, Vec<u8>)> = Vec::new();

    for input in inputs {
        let pk_x = Felt::from_hex(&input.public_key.x)
            .map_err(|e| JsValue::from_str(&format!("Invalid public key x: {e}")))?;
        let pk_y = Felt::from_hex(&input.public_key.y)
            .map_err(|e| JsValue::from_str(&format!("Invalid public key y: {e}")))?;

        let pk = PublicKey::new(
            ProjectivePoint::from_affine(pk_x, pk_y)
                .map_err(|e| JsValue::from_str(&format!("Invalid public key: {e:?}")))?,
        );

        let proof: KeyOwnershipProof = input.proof.into();
        let context = input.context.into_bytes();

        keys_with_proofs.push((pk, proof, context));
    }

    let aggregate = MentalPokerProtocol::compute_aggregate_key(&keys_with_proofs)
        .map_err(|e| JsValue::from_str(&format!("Failed to aggregate keys: {e}")))?;

    let agg_affine = aggregate
        .point
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid aggregate key"))?;

    Ok(WasmPublicKey {
        x: format!("{:#x}", agg_affine.x()),
        y: format!("{:#x}", agg_affine.y()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_generate_keypair() {
        let result = generate_keypair("test_player");
        assert!(result.is_ok());
        let keypair = result.unwrap();
        assert!(keypair.secret_key.starts_with("0x"));
        assert!(keypair.public_key.x.starts_with("0x"));
    }

    #[wasm_bindgen_test]
    fn test_player_from_secret_key() {
        let keypair = generate_keypair("test").unwrap();
        let player = player_from_secret_key(&keypair.secret_key);
        assert!(player.is_ok());
        let p = player.unwrap();
        assert_eq!(p.public_key().x, keypair.public_key.x);
    }

    #[wasm_bindgen_test]
    fn test_verify_key_ownership() {
        let keypair = generate_keypair("test_context").unwrap();
        let valid = verify_key_ownership(
            &keypair.public_key,
            &keypair.key_ownership_proof,
            "test_context",
        );
        assert!(valid.is_ok());
        assert!(valid.unwrap());

        // Wrong context should fail
        let invalid = verify_key_ownership(
            &keypair.public_key,
            &keypair.key_ownership_proof,
            "wrong_context",
        );
        assert!(invalid.is_ok());
        assert!(!invalid.unwrap());
    }

    #[wasm_bindgen_test]
    fn test_aggregate_public_keys() {
        let kp1 = generate_keypair("player1").unwrap();
        let kp2 = generate_keypair("player2").unwrap();

        let inputs = vec![
            WasmAggregateKeyInput::new(
                kp1.public_key.clone(),
                kp1.key_ownership_proof.clone(),
                "player1".to_string(),
            ),
            WasmAggregateKeyInput::new(
                kp2.public_key.clone(),
                kp2.key_ownership_proof.clone(),
                "player2".to_string(),
            ),
        ];

        let result = aggregate_public_keys(inputs);
        assert!(result.is_ok());
        let agg = result.unwrap();
        assert!(agg.x.starts_with("0x"));
        assert!(agg.y.starts_with("0x"));
    }
}
