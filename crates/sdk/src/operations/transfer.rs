use super::{
    shared::{create_affine_point, verify_cipher_encrypts_balance},
    Audit, TransferParams, TransferProof,
};
use crate::{crypto::encrypt_for_auditor, TongoAccount};
use krusty_kms_common::{ElGamalCiphertext, KmsError, ProofOfTransfer, Result};
use krusty_kms_crypto::{poseidon_hash_many, range, AuditPrefixData, AuditProver, StarkCurve};
use starknet_types_core::felt::Felt;

/// Sequential fallback for `rayon::join` when parallel support is disabled.
#[cfg(not(feature = "parallel"))]
fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA,
    B: FnOnce() -> RB,
{
    (a(), b())
}

/// Cairo string 'transfer'.
const TRANSFER_CAIRO_STRING: Felt = Felt::from_hex_unchecked("0x7472616e73666572");

/// Execute a transfer operation.
///
/// Implements the full Tongo transfer protocol with range proofs.
/// Reference: typescript-reference/tongo-sdk/src/provers/transfer.ts:86-186
///
/// Generates zero-knowledge proofs that:
/// 1. Knowledge of private key (PoE for y = g^x)
/// 2. Correct encryption for recipient and self (PoE2 proofs)
/// 3. Transfer amount is in valid range [0, 2^bit_size - 1]
/// 4. Leftover balance is in valid range [0, 2^bit_size - 1]
/// 5. Balance equations verify correctly
///
/// # Errors
///
/// Returns [`KmsError`] if:
/// - Amount is zero (`InvalidAmount`)
/// - Insufficient balance for transfer (`InsufficientBalance`)
/// - Public key or recipient key point is at infinity (`PointAtInfinity`)
/// - Range proof generation fails (`RangeProofError`)
/// - Point conversion fails during encryption or audit proof generation
/// - Scalar multiplication or point addition fails
///
pub fn transfer(account: &TongoAccount, params: TransferParams) -> Result<TransferProof> {
    // Validation
    if params.amount == 0 {
        return Err(KmsError::InvalidAmount(
            "Amount must be greater than zero".to_string(),
        ));
    }

    if !account.has_sufficient_balance(params.amount) {
        return Err(KmsError::InsufficientBalance);
    }

    // Setup variables
    let x = account.owner_private_key().expose_secret();
    let y = account.owner_public_key().clone();
    let to = &params.recipient_public_key;
    let b = params.amount;
    let b0 = account.balance();
    let g = StarkCurve::generator();
    let h = StarkCurve::generator_h();

    // Verify storedBalance is an encryption of the claimed balance: g^b = L0 - R0^x
    // (same consistency check as withdraw)
    verify_cipher_encrypts_balance(&params.current_balance, x, b0, &g)?;

    // Get affine coordinates for prefix computation
    let y_affine = y.to_affine().map_err(|_| KmsError::PointAtInfinity)?;
    let to_affine = to.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Compute leftover balance
    let b_left = b0 - b;

    // Pre-generate random values for both range proofs to break circular dependency
    use krusty_kms_crypto::random::random_felts;
    let random_values_1 = random_felts(params.bit_size);
    let random_values_2 = random_felts(params.bit_size);
    let r = range::compute_total_randomness(&random_values_1)?;
    let r2 = range::compute_total_randomness(&random_values_2)?;

    // Create cipher balances using pre-computed r and r2
    // transferBalanceSelf: encryption for sender
    let transfer_balance_self_l = {
        let g_b = StarkCurve::mul(&Felt::from(b), Some(&g));
        let y_r = StarkCurve::mul(&r, Some(&y));
        StarkCurve::add(&g_b, &y_r)
    };
    let transfer_balance_self_r = StarkCurve::mul(&r, Some(&g));

    // transferBalance: encryption for recipient
    let transfer_balance_l = {
        let g_b = StarkCurve::mul(&Felt::from(b), Some(&g));
        let to_r = StarkCurve::mul(&r, Some(to));
        StarkCurve::add(&g_b, &to_r)
    };
    let transfer_balance_r = StarkCurve::mul(&r, Some(&g));

    // auxiliarCipher: V = g^b * h^r, R_aux = g^r
    let r_aux = StarkCurve::mul(&r, Some(&g));
    let v = {
        let g_b = StarkCurve::mul(&Felt::from(b), Some(&g));
        let h_r = StarkCurve::mul(&r, Some(&h));
        StarkCurve::add(&g_b, &h_r)
    };

    // auxiliarCipher2: V2 = g^b_left * h^r2, R_aux2 = g^r2
    let r_aux2 = StarkCurve::mul(&r2, Some(&g));
    let v2 = {
        let g_b_left = StarkCurve::mul(&Felt::from(b_left), Some(&g));
        let h_r2 = StarkCurve::mul(&r2, Some(&h));
        StarkCurve::add(&g_b_left, &h_r2)
    };

    // Convert all cipher balance points to affine for prefix
    let current_l_affine = params
        .current_balance
        .l
        .to_affine()
        .map_err(|_| KmsError::PointAtInfinity)?;
    let current_r_affine = params
        .current_balance
        .r
        .to_affine()
        .map_err(|_| KmsError::PointAtInfinity)?;
    let tbs_l_affine = transfer_balance_self_l
        .to_affine()
        .map_err(|_| KmsError::PointAtInfinity)?;
    let tbs_r_affine = transfer_balance_self_r
        .to_affine()
        .map_err(|_| KmsError::PointAtInfinity)?;
    let tb_l_affine = transfer_balance_l
        .to_affine()
        .map_err(|_| KmsError::PointAtInfinity)?;
    let tb_r_affine = transfer_balance_r
        .to_affine()
        .map_err(|_| KmsError::PointAtInfinity)?;
    let v_affine = v.to_affine().map_err(|_| KmsError::PointAtInfinity)?;
    let r_aux_affine = r_aux.to_affine().map_err(|_| KmsError::PointAtInfinity)?;
    let v2_affine = v2.to_affine().map_err(|_| KmsError::PointAtInfinity)?;
    let r_aux2_affine = r_aux2.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Build prefix matching tongo-sdk prefixTransfer
    let prefix_inputs = vec![
        params.chain_id,
        params.tongo_address,
        params.sender_address,
        TRANSFER_CAIRO_STRING,
        y_affine.x(),
        y_affine.y(),
        to_affine.x(),
        to_affine.y(),
        params.nonce,
        current_l_affine.x(),
        current_l_affine.y(),
        current_r_affine.x(),
        current_r_affine.y(),
        tbs_l_affine.x(),
        tbs_l_affine.y(),
        tbs_r_affine.x(),
        tbs_r_affine.y(),
        tb_l_affine.x(),
        tb_l_affine.y(),
        tb_r_affine.x(),
        tb_r_affine.y(),
        v_affine.x(),
        v_affine.y(),
        r_aux_affine.x(),
        r_aux_affine.y(),
        v2_affine.x(),
        v2_affine.y(),
        r_aux2_affine.x(),
        r_aux2_affine.y(),
    ];
    let prefix = poseidon_hash_many(&prefix_inputs);

    // Generate both range proofs using pre-generated randomness
    #[cfg(feature = "parallel")]
    let (result1, result2) = rayon::join(
        || range::prove_with_randomness(b, params.bit_size, &g, &h, &prefix, &random_values_1),
        || range::prove_with_randomness(b_left, params.bit_size, &g, &h, &prefix, &random_values_2),
    );
    #[cfg(not(feature = "parallel"))]
    let (result1, result2) = join(
        || range::prove_with_randomness(b, params.bit_size, &g, &h, &prefix, &random_values_1),
        || range::prove_with_randomness(b_left, params.bit_size, &g, &h, &prefix, &random_values_2),
    );
    let (range, _r) = result1?;
    let (range2, _r2) = result2?;

    // Compute G = R0 - transferBalanceSelf.R
    let g_point = {
        let r_transfer_affine = StarkCurve::projective_to_affine(&transfer_balance_self_r)?;
        let neg_r_transfer = StarkCurve::affine_to_projective(&create_affine_point(
            r_transfer_affine.x(),
            -r_transfer_affine.y(),
        )?);
        StarkCurve::add(&params.current_balance.r, &neg_r_transfer)
    };

    // Generate 5 random k values for commitments
    let kx = krusty_kms_crypto::scalar::random_felt();
    let kb = krusty_kms_crypto::scalar::random_felt();
    let kr = krusty_kms_crypto::scalar::random_felt();
    let kb2 = krusty_kms_crypto::scalar::random_felt();
    let kr2_k = krusty_kms_crypto::scalar::random_felt();

    // Compute 8 commitments
    let a_x = StarkCurve::mul(&kx, Some(&g));
    let a_r = StarkCurve::mul(&kr, Some(&g));
    let a_r2 = StarkCurve::mul(&kr2_k, Some(&g));

    let a_b = {
        let g_kb = StarkCurve::mul(&kb, Some(&g));
        let y_kr = StarkCurve::mul(&kr, Some(&y));
        StarkCurve::add(&g_kb, &y_kr)
    };

    let a_bar = {
        let g_kb = StarkCurve::mul(&kb, Some(&g));
        let to_kr = StarkCurve::mul(&kr, Some(to));
        StarkCurve::add(&g_kb, &to_kr)
    };

    let a_v = {
        let g_kb = StarkCurve::mul(&kb, Some(&g));
        let h_kr = StarkCurve::mul(&kr, Some(&h));
        StarkCurve::add(&g_kb, &h_kr)
    };

    let a_b2 = {
        let g_kb2 = StarkCurve::mul(&kb2, Some(&g));
        let g_kx = StarkCurve::mul(&kx, Some(&g_point));
        StarkCurve::add(&g_kb2, &g_kx)
    };

    let a_v2 = {
        let g_kb2 = StarkCurve::mul(&kb2, Some(&g));
        let h_kr2 = StarkCurve::mul(&kr2_k, Some(&h));
        StarkCurve::add(&g_kb2, &h_kr2)
    };

    // Compute challenge from prefix and all 8 commitments
    let challenge = krusty_kms_crypto::hash::compute_poseidon_challenge(
        &prefix,
        &[&a_x, &a_r, &a_r2, &a_b, &a_b2, &a_v, &a_v2, &a_bar],
    )?;

    // Compute 5 scalar responses s = k + value * c
    let s_x = krusty_kms_crypto::scalar::scalar_add(
        &kx,
        &krusty_kms_crypto::scalar::scalar_mul(&challenge, x)?,
    )?;
    let s_b = krusty_kms_crypto::scalar::scalar_add(
        &kb,
        &krusty_kms_crypto::scalar::scalar_mul(&challenge, &Felt::from(b))?,
    )?;
    let s_r = krusty_kms_crypto::scalar::scalar_add(
        &kr,
        &krusty_kms_crypto::scalar::scalar_mul(&challenge, &r)?,
    )?;
    let s_b2 = krusty_kms_crypto::scalar::scalar_add(
        &kb2,
        &krusty_kms_crypto::scalar::scalar_mul(&challenge, &Felt::from(b_left))?,
    )?;
    let s_r2 = krusty_kms_crypto::scalar::scalar_add(
        &kr2_k,
        &krusty_kms_crypto::scalar::scalar_mul(&challenge, &r2)?,
    )?;

    // Assemble ProofOfTransfer (without r_aux/r_aux2 — now in auxiliar ciphers)
    let proof = ProofOfTransfer {
        a_x: krusty_kms_common::SerializablePoint::try_from_projective(&a_x)?,
        a_r: krusty_kms_common::SerializablePoint::try_from_projective(&a_r)?,
        a_r2: krusty_kms_common::SerializablePoint::try_from_projective(&a_r2)?,
        a_b: krusty_kms_common::SerializablePoint::try_from_projective(&a_b)?,
        a_b2: krusty_kms_common::SerializablePoint::try_from_projective(&a_b2)?,
        a_v: krusty_kms_common::SerializablePoint::try_from_projective(&a_v)?,
        a_v2: krusty_kms_common::SerializablePoint::try_from_projective(&a_v2)?,
        a_bar: krusty_kms_common::SerializablePoint::try_from_projective(&a_bar)?,
        s_x,
        s_r,
        s_b,
        s_b2,
        s_r2,
        range,
        range2,
    };

    // Package auxiliar ciphers
    let auxiliar_cipher = ElGamalCiphertext { l: v, r: r_aux };
    let auxiliar_cipher2 = ElGamalCiphertext { l: v2, r: r_aux2 };

    // Compute new cipher balance
    let new_balance_cipher_l = {
        let l_transfer_affine = StarkCurve::projective_to_affine(&transfer_balance_self_l)?;
        let neg_l_transfer = StarkCurve::affine_to_projective(&create_affine_point(
            l_transfer_affine.x(),
            -l_transfer_affine.y(),
        )?);
        StarkCurve::add(&params.current_balance.l, &neg_l_transfer)
    };

    let new_balance_cipher_r = {
        let r_transfer_affine = StarkCurve::projective_to_affine(&transfer_balance_self_r)?;
        let neg_r_transfer = StarkCurve::affine_to_projective(&create_affine_point(
            r_transfer_affine.x(),
            -r_transfer_affine.y(),
        )?);
        StarkCurve::add(&params.current_balance.r, &neg_r_transfer)
    };

    let new_balance_cipher = ElGamalCiphertext {
        l: new_balance_cipher_l,
        r: new_balance_cipher_r,
    };

    // Generate audits if auditor is configured
    let (audit_balance, audit_transfer) = if let Some(ref auditor_key) = params.auditor_pub_key {
        let audit_prefix = AuditPrefixData {
            chain_id: params.chain_id,
            tongo_address: params.tongo_address,
            sender_address: params.sender_address,
            user_pub_key: y.clone(),
        };
        let (audit_balance_proof, audited_balance) = AuditProver::prove_with_validation(
            account.owner_private_key().expose_secret(),
            b_left,
            &new_balance_cipher,
            auditor_key,
            false,
            Some(&audit_prefix),
        )?;

        let (audit_balance_hint_ct, audit_balance_hint_nonce) = encrypt_for_auditor(
            b_left,
            account.owner_private_key().expose_secret(),
            auditor_key,
        )?;

        let transfer_cipher_self = ElGamalCiphertext {
            l: transfer_balance_self_l.clone(),
            r: transfer_balance_self_r.clone(),
        };

        let (audit_transfer_proof, audited_transfer) = AuditProver::prove(
            account.owner_private_key().expose_secret(),
            b,
            &transfer_cipher_self,
            auditor_key,
            Some(&audit_prefix),
        )?;

        let (audit_transfer_hint_ct, audit_transfer_hint_nonce) =
            encrypt_for_auditor(b, account.owner_private_key().expose_secret(), auditor_key)?;

        (
            Some(Audit {
                audited_balance,
                hint_ciphertext: audit_balance_hint_ct,
                hint_nonce: audit_balance_hint_nonce,
                proof: audit_balance_proof,
            }),
            Some(Audit {
                audited_balance: audited_transfer,
                hint_ciphertext: audit_transfer_hint_ct,
                hint_nonce: audit_transfer_hint_nonce,
                proof: audit_transfer_proof,
            }),
        )
    } else {
        (None, None)
    };

    Ok(TransferProof {
        transfer_balance_l,
        transfer_balance_r,
        transfer_balance_self_l,
        transfer_balance_self_r,
        proof,
        auxiliar_cipher,
        auxiliar_cipher2,
        new_balance_cipher,
        audit_balance,
        audit_transfer,
    })
}
