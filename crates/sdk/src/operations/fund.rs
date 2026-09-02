use super::{Audit, FundParams, FundProof};
use crate::{crypto::encrypt_for_auditor, TongoAccount};
use krusty_kms_common::{ElGamalCiphertext, KmsError, Result};
use krusty_kms_crypto::{
    poseidon_hash_many, AuditPrefixData, AuditProver, ProofOfExponentiation, StarkCurve,
};
use starknet_types_core::felt::Felt;

/// Cairo string 'fund'.
const FUND_CAIRO_STRING: Felt = Felt::from_hex_unchecked("0x66756e64");

/// Balance after funding. A `u128` wrap here would prove a wrapped balance to
/// the auditor, so it is rejected like every other amount overflow.
fn funded_balance(balance: u128, amount: u128) -> Result<u128> {
    balance
        .checked_add(amount)
        .ok_or_else(|| KmsError::InvalidAmount("funded balance overflow".to_string()))
}

/// Execute a fund operation.
///
/// Generates a proof that the user knows the private key for their account.
/// This proves authorization to fund the account.
///
/// Reference: typescript-reference/tongo-sdk/src/provers/fund.ts:58-89
///
/// # Errors
///
/// Returns [`KmsError`] if:
/// - Amount is zero, or the funded balance overflows `u128` (`InvalidAmount`)
/// - Public key point is at infinity (`PointAtInfinity`)
/// - Proof generation fails (`ProofGenerationError`)
/// - Point conversion fails during audit proof generation
///
/// # Cyclomatic Complexity: 2
pub fn fund(account: &TongoAccount, params: FundParams) -> Result<FundProof> {
    if params.amount == 0 {
        return Err(KmsError::InvalidAmount(
            "Amount must be greater than zero".to_string(),
        ));
    }

    // Compute public key y = g^x
    let y = account.owner_public_key().clone();

    // Get affine coordinates for prefix computation
    let y_affine = y.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Compute prefix using Poseidon hash
    // prefix = poseidon([chain_id, tongo_address, sender_address, FUND_CAIRO_STRING, y.x, y.y, amount, nonce])
    let prefix_inputs = vec![
        params.chain_id,
        params.tongo_address,
        params.sender_address,
        FUND_CAIRO_STRING,
        y_affine.x(),
        y_affine.y(),
        Felt::from(params.amount),
        params.nonce,
    ];
    let prefix = poseidon_hash_many(&prefix_inputs);

    // Generate proof of knowledge of private key: y = g^x
    // This proves the account owner authorized this fund operation
    let (_, proof) =
        ProofOfExponentiation::prove(account.owner_private_key().expose_secret(), &prefix)?;

    // Generate audit if auditor is configured
    let audit = if let Some(ref auditor_key) = params.auditor_pub_key {
        // CRITICAL: The Cairo contract adds the fund amount to balance BEFORE verifying audit
        // So we must prove the balance AFTER funding, not before!
        // See Tongo.cairo:fund() - it calls _add_balance() before _handle_audit_balance()
        let new_balance = funded_balance(account.balance(), params.amount)?;

        // Compute the new cipher balance after funding
        // The contract adds: cipher = CipherBalanceTrait::new(to, amount, 'fund')
        // which is: L = g^amount + y^FUND_CAIRO_STRING, R = g^FUND_CAIRO_STRING
        let fund_cipher_l = {
            let g_amount =
                StarkCurve::mul(&Felt::from(params.amount), Some(&StarkCurve::generator()));
            let y_r = StarkCurve::mul(&FUND_CAIRO_STRING, Some(account.owner_public_key()));
            StarkCurve::add(&g_amount, &y_r)
        };
        let fund_cipher_r = StarkCurve::mul(&FUND_CAIRO_STRING, Some(&StarkCurve::generator()));

        let new_cipher_balance = ElGamalCiphertext {
            l: StarkCurve::add(&params.current_balance.l, &fund_cipher_l),
            r: StarkCurve::add(&params.current_balance.r, &fund_cipher_r),
        };

        // Generate audit proof using the NEW balance (after funding)
        let audit_prefix = AuditPrefixData {
            chain_id: params.chain_id,
            tongo_address: params.tongo_address,
            sender_address: params.sender_address,
            user_pub_key: y.clone(),
        };
        let (audit_proof, audited_balance) = AuditProver::prove(
            account.owner_private_key().expose_secret(),
            new_balance,
            &new_cipher_balance,
            auditor_key,
            Some(&audit_prefix),
        )?;

        // Generate audit hint (XChaCha20-Poly1305 encryption of the plaintext balance)
        // The auditor can decrypt this using ECDH with user's public key
        let (audit_hint_ct, audit_hint_nonce) = encrypt_for_auditor(
            new_balance,
            account.owner_private_key().expose_secret(),
            auditor_key,
        )?;

        Some(Audit {
            audited_balance,
            hint_ciphertext: audit_hint_ct,
            hint_nonce: audit_hint_nonce,
            proof: audit_proof,
        })
    } else {
        None
    };

    Ok(FundProof {
        y,
        proof,
        amount: params.amount,
        audit,
    })
}
