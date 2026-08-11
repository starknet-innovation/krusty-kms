use super::{shared::verify_cipher_encrypts_balance, Audit, RagequitParams, RagequitProof};
use crate::{crypto::encrypt_for_auditor, TongoAccount};
use krusty_kms_common::{ElGamalCiphertext, KmsError, Result};
use krusty_kms_crypto::{
    hash, poseidon_hash_many, scalar, AuditPrefixData, AuditProver, StarkCurve,
};
use starknet_types_core::felt::Felt;

/// Cairo string 'ragequit'.
const RAGEQUIT_CAIRO_STRING: Felt = Felt::from_hex_unchecked("0x7261676571756974");

/// Execute a ragequit operation.
///
/// Withdraws the ENTIRE balance from the Tongo account, leaving a balance of 0.
/// Simpler than withdraw - no range proofs needed since we're withdrawing everything.
///
/// Reference: typescript-reference/tongo-sdk/src/provers/ragequit.ts:65-105
///
/// Generates zero-knowledge proofs that:
/// 1. Knowledge of private key (PoE for y = g^x)
/// 2. The stored cipher encrypts the full amount being withdrawn
///
/// # Errors
///
/// Returns [`KmsError`] if:
/// - Public key point is at infinity (`PointAtInfinity`)
/// - Point conversion fails during cipher decryption or audit proof generation
/// - Invalid affine point construction
/// - Chaum-Pedersen proof generation fails
///
/// # Cyclomatic Complexity: 2
pub fn ragequit(account: &TongoAccount, params: RagequitParams) -> Result<RagequitProof> {
    let x: &Felt = account.owner_private_key().expose_secret();
    let g = StarkCurve::generator();

    // Compute y = g^x
    let y = account.owner_public_key().clone();
    let y_affine = y.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Extract L0, R0 from current cipherbalance
    let l0 = &params.current_balance.l;
    let r0 = &params.current_balance.r;

    // Verify storedBalance is an encryption of the full balance: g^b = L0 - R0^x
    // Reference: ragequit.ts:78-81
    verify_cipher_encrypts_balance(&params.current_balance, x, account.balance(), &g).map_err(
        |e| match e {
            KmsError::CryptoError(_) => KmsError::CryptoError(
                "storedBalance is not an encryption of full balance".to_string(),
            ),
            other => other,
        },
    )?;

    // Full amount is the entire account balance
    let full_amount = account.balance();

    // Convert current balance cipher points to affine for prefix
    let l0_affine = l0.to_affine().map_err(|_| KmsError::PointAtInfinity)?;
    let r0_affine = r0.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Compute prefix: [chain_id, tongo_address, sender_address, RAGEQUIT, y.x, y.y, nonce, amount, to,
    //                   L0.x, L0.y, R0.x, R0.y]
    let prefix_inputs = vec![
        params.chain_id,
        params.tongo_address,
        params.sender_address,
        RAGEQUIT_CAIRO_STRING,
        y_affine.x(),
        y_affine.y(),
        params.nonce,
        Felt::from(full_amount),
        params.recipient_address,
        l0_affine.x(),
        l0_affine.y(),
        r0_affine.x(),
        r0_affine.y(),
    ];
    let prefix = poseidon_hash_many(&prefix_inputs);

    // Generate random kx
    // Reference: ragequit.ts:93
    let kx = krusty_kms_crypto::scalar::random_felt();

    // Compute commitments
    // Ax = g^kx (ragequit.ts:95)
    // AR = R0^kx (ragequit.ts:96)
    let a_x = StarkCurve::mul(&kx, Some(&g));
    let a_r = StarkCurve::mul(&kx, Some(r0));

    // Compute challenge c = H(prefix, [Ax, AR])
    // Reference: ragequit.ts:98
    let c = hash::compute_poseidon_challenge(&prefix, &[&a_x, &a_r])?;

    // Compute response: sx = kx + c*x
    // Reference: ragequit.ts:99
    let c_x = scalar::scalar_mul(&c, x)?;
    let sx = scalar::scalar_add(&kx, &c_x)?;

    // Generate audit proof if auditor key is provided
    // Note: After ragequit, balance is 0 with cipher (y, g) using randomness=1
    // Reference: ragequit.ts:103 - newBalance = createCipherBalance(y, 0n, 1n)
    // Reference: utils.ts:34-37 - when amount=0: L = y*random, R = g*random
    let audit = if let Some(auditor_key) = params.auditor_key {
        // New balance cipher after ragequit: createCipherBalance(y, 0, 1)
        // Since amount=0, only randomness contributes: L = y*1 = y, R = g*1 = g
        let new_balance_cipher = ElGamalCiphertext {
            l: y.clone(), // L = y*1 = y
            r: g.clone(), // R = g*1 = g
        };

        // Curve scalar_mul now correctly maps 0 * g -> identity, so local
        // validation matches Cairo (cipher (y, g) decrypts to g^0 = O).
        let audit_prefix = AuditPrefixData {
            chain_id: params.chain_id,
            tongo_address: params.tongo_address,
            sender_address: params.sender_address,
            user_pub_key: y.clone(),
        };
        let (audit_proof, audited_balance) = AuditProver::prove_with_validation(
            account.owner_private_key().expose_secret(),
            0, // Balance after ragequit is 0
            &new_balance_cipher,
            &auditor_key,
            true, // Re-enabled: 0*g identity fix makes validation sound
            Some(&audit_prefix),
        )?;

        // Encrypt zero balance for auditor (after ragequit balance is 0)
        let (audit_hint_ct, audit_hint_nonce) = encrypt_for_auditor(
            0, // Balance after ragequit is 0
            account.owner_private_key().expose_secret(),
            &auditor_key,
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

    Ok(RagequitProof {
        y,
        a_x,
        a_r,
        sx,
        amount: full_amount,
        recipient: params.recipient_address,
        audit,
    })
}
