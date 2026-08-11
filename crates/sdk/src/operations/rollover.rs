use super::{RolloverParams, RolloverProof};
use crate::TongoAccount;
use krusty_kms_common::{KmsError, Result};
use krusty_kms_crypto::{poseidon_hash_many, ProofOfExponentiation};
use starknet_types_core::felt::Felt;

/// Cairo string 'rollover'.
const ROLLOVER_CAIRO_STRING: Felt = Felt::from_hex_unchecked("0x726f6c6c6f766572");

/// Execute a rollover operation.
///
/// Generates a proof that the pending balance is being activated.
///
/// Uses Okamoto's protocol with two generators (G, H) to prove:
/// new_balance_commitment = G^current_balance * H^pending_balance
///
/// # Errors
///
/// Returns [`KmsError`] if:
/// - Public key point is at infinity (`PointAtInfinity`)
/// - Invalid rollover string encoding (`CryptoError`)
/// - Proof generation fails (`ProofGenerationError`)
///
/// # Cyclomatic Complexity: 1
pub fn rollover(account: &TongoAccount, params: RolloverParams) -> Result<RolloverProof> {
    // Compute public key y = g^x (same as fund operation)
    let y = account.owner_public_key().clone();

    // Get affine coordinates for prefix computation
    let y_affine = y.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Compute prefix using Poseidon hash (MUST match contract exactly!)
    // prefix = poseidon([chain_id, tongo_address, sender_address, 'rollover', y.x, y.y, nonce])
    let prefix_inputs = vec![
        params.chain_id,
        params.tongo_address,
        params.sender_address,
        ROLLOVER_CAIRO_STRING,
        y_affine.x(),
        y_affine.y(),
        params.nonce,
    ];
    let prefix = poseidon_hash_many(&prefix_inputs);

    // Generate proof of knowledge of private key: y = g^x
    // This proves the account owner authorized this rollover operation
    let (_, proof) =
        ProofOfExponentiation::prove(account.owner_private_key().expose_secret(), &prefix)?;

    Ok(RolloverProof {
        y,
        proof,
        pending_amount: account.pending_balance(),
    })
}
