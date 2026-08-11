use super::{
    shared::{create_affine_point, verify_cipher_encrypts_balance},
    Audit, WithdrawParams, WithdrawProof,
};
use crate::{crypto::encrypt_for_auditor, TongoAccount};
use krusty_kms_common::{ElGamalCiphertext, KmsError, Result};
use krusty_kms_crypto::{
    hash, poseidon_hash_many, range, scalar, AuditPrefixData, AuditProver, StarkCurve,
};
use starknet_types_core::felt::Felt;

/// Cairo string 'withdraw'.
const WITHDRAW_CAIRO_STRING: Felt = Felt::from_hex_unchecked("0x7769746864726177");

/// Execute a withdraw operation.
///
/// Generates a complex proof that:
/// 1. User knows the private key
/// 2. Current balance cipher encrypts the claimed balance
/// 3. Leftover balance (after withdrawal) is in valid range [0, 2^bit_size - 1]
/// 4. The leftover cipher is correctly formed
///
/// # Reference
/// typescript-reference/tongo-sdk/src/provers/withdraw.ts:proveWithdraw()
///
/// # Errors
///
/// Returns [`KmsError`] if:
/// - Amount is zero (`InvalidAmount`)
/// - Insufficient balance for withdrawal (`InsufficientBalance`)
/// - Public key point is at infinity (`PointAtInfinity`)
/// - Range proof generation fails for leftover balance (`RangeProofError`)
/// - Point conversion fails during cipher or audit proof generation
/// - Invalid affine point construction
///
/// # Cyclomatic Complexity: 4
pub fn withdraw(account: &TongoAccount, params: WithdrawParams) -> Result<WithdrawProof> {
    if params.amount == 0 {
        return Err(KmsError::InvalidAmount(
            "Amount must be greater than zero".to_string(),
        ));
    }

    if !account.has_sufficient_balance(params.amount) {
        return Err(KmsError::InsufficientBalance);
    }

    let x: &Felt = account.owner_private_key().expose_secret();
    let g = StarkCurve::generator();
    let h = StarkCurve::generator_h();

    // Compute y = g^x
    let y = account.owner_public_key().clone();
    let y_affine = y.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Extract L0, R0 from current cipherbalance
    let l0 = &params.current_balance.l;
    let r0 = &params.current_balance.r;

    // Verify storedBalance is an encryption of the balance: g^b = L0 - R0^x
    verify_cipher_encrypts_balance(&params.current_balance, x, account.balance(), &g)?;

    // Compute leftover balance
    let left = account.balance() - params.amount;

    // Pre-generate random values for range proof to break circular dependency:
    // prefix needs cipher coords -> coords need r -> r comes from range proof -> range proof needs prefix
    use krusty_kms_crypto::random::random_felts;
    let random_values = random_felts(params.bit_size);
    let r = range::compute_total_randomness(&random_values)?;

    // Compute auxiliar cipher: V = g^b_left * h^r, R_aux = g^r
    let r_aux = StarkCurve::mul(&r, Some(&g));
    let v = {
        let g_left = StarkCurve::mul(&Felt::from(left), Some(&g));
        let h_r = StarkCurve::mul(&r, Some(&h));
        StarkCurve::add(&g_left, &h_r)
    };

    // Convert points to affine for prefix computation
    let l0_affine = l0.to_affine().map_err(|_| KmsError::PointAtInfinity)?;
    let r0_affine = r0.to_affine().map_err(|_| KmsError::PointAtInfinity)?;
    let v_affine = v.to_affine().map_err(|_| KmsError::PointAtInfinity)?;
    let r_aux_affine = r_aux.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Compute prefix: [chain_id, tongo_address, sender_address, WITHDRAW, y.x, y.y, nonce, amount, to,
    //                   L0.x, L0.y, R0.x, R0.y, V.x, V.y, R_aux.x, R_aux.y]
    let prefix_inputs = vec![
        params.chain_id,
        params.tongo_address,
        params.sender_address,
        WITHDRAW_CAIRO_STRING,
        y_affine.x(),
        y_affine.y(),
        params.nonce,
        Felt::from(params.amount),
        params.recipient_address,
        l0_affine.x(),
        l0_affine.y(),
        r0_affine.x(),
        r0_affine.y(),
        v_affine.x(),
        v_affine.y(),
        r_aux_affine.x(),
        r_aux_affine.y(),
    ];
    let prefix = poseidon_hash_many(&prefix_inputs);

    // Generate range proof for leftover balance using pre-generated randomness
    let (range, _r) =
        range::prove_with_randomness(left, params.bit_size, &g, &h, &prefix, &random_values)?;

    // Generate random values for commitments
    let commitment_randoms = random_felts(3);
    let (kb, kx, kr) = (
        &commitment_randoms[0],
        &commitment_randoms[1],
        &commitment_randoms[2],
    );

    // Compute commitments
    let a_x = StarkCurve::mul(kx, Some(&g));
    let a_r = StarkCurve::mul(kr, Some(&g));
    let g_kb = StarkCurve::mul(kb, Some(&g));
    let r0_kx = StarkCurve::mul(kx, Some(r0));
    let h_kr = StarkCurve::mul(kr, Some(&h));

    let a = StarkCurve::add(&g_kb, &r0_kx);
    let a_v = StarkCurve::add(&g_kb, &h_kr);

    // Compute challenge c = H(prefix, [A_x, A_r, A, A_v])
    let c = hash::compute_poseidon_challenge(&prefix, &[&a_x, &a_r, &a, &a_v])?;

    // Compute responses: s = k + c*value
    let c_left = scalar::scalar_mul(&c, &Felt::from(left))?;
    let sb = scalar::scalar_add(kb, &c_left)?;

    let c_x = scalar::scalar_mul(&c, x)?;
    let sx = scalar::scalar_add(kx, &c_x)?;

    let c_r = scalar::scalar_mul(&c, &r)?;
    let sr = scalar::scalar_add(kr, &c_r)?;

    // Package auxiliar cipher
    let auxiliar_cipher = ElGamalCiphertext { l: v, r: r_aux };

    // Generate audit proof if auditor key is provided
    let audit = if let Some(auditor_key) = params.auditor_key {
        // Create cipher for withdraw amount using fixed randomness "withdraw"
        let cipher_l = {
            let g_amount = StarkCurve::mul(&Felt::from(params.amount), Some(&g));
            let y_r = StarkCurve::mul(&WITHDRAW_CAIRO_STRING, Some(&y));
            StarkCurve::add(&g_amount, &y_r)
        };
        let cipher_r = StarkCurve::mul(&WITHDRAW_CAIRO_STRING, Some(&g));

        // Compute leftover cipher = current_cipher - withdraw_cipher
        let cipher_l_affine = StarkCurve::projective_to_affine(&cipher_l)?;
        let neg_cipher_l = StarkCurve::affine_to_projective(&create_affine_point(
            cipher_l_affine.x(),
            -cipher_l_affine.y(),
        )?);
        let l_left = StarkCurve::add(l0, &neg_cipher_l);

        let cipher_r_affine = StarkCurve::projective_to_affine(&cipher_r)?;
        let neg_cipher_r = StarkCurve::affine_to_projective(&create_affine_point(
            cipher_r_affine.x(),
            -cipher_r_affine.y(),
        )?);
        let r_left = StarkCurve::add(r0, &neg_cipher_r);

        let leftover_cipher = ElGamalCiphertext {
            l: l_left,
            r: r_left,
        };

        let audit_prefix = AuditPrefixData {
            chain_id: params.chain_id,
            tongo_address: params.tongo_address,
            sender_address: params.sender_address,
            user_pub_key: y.clone(),
        };
        let (audit_proof, audited_balance) = AuditProver::prove_with_validation(
            account.owner_private_key().expose_secret(),
            left,
            &leftover_cipher,
            &auditor_key,
            false,
            Some(&audit_prefix),
        )?;

        let (audit_hint_ct, audit_hint_nonce) = encrypt_for_auditor(
            left,
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

    Ok(WithdrawProof {
        y,
        a_x,
        a_r,
        a,
        a_v,
        sx,
        sb,
        sr,
        auxiliar_cipher,
        range,
        amount: params.amount,
        recipient: params.recipient_address,
        audit,
    })
}
