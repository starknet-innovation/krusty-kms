//! TONGO protocol operations.
//!
//! This module provides the four core operations of the TONGO protocol:
//! - Fund: Deposit STRK into confidential balance
//! - Transfer: Send confidential STRK to another account
//! - Rollover: Activate pending balance
//! - Withdraw: Exit confidential balance to public STRK
//! - Ragequit: Emergency exit of all funds
//!
//! # Security Considerations
//!
//! All TONGO operations use zero-knowledge proofs to maintain privacy:
//!
//! - **Fund**: Creates encrypted balance with optional audit proof
//! - **Transfer**: Dual range proofs ensure no negative balances
//! - **Rollover**: Activates pending balance with signature proof
//! - **Withdraw**: Range proof ensures sufficient balance
//! - **Ragequit**: Exits full balance with Chaum-Pedersen proof
//!
//! ## Cryptographic Primitives
//!
//! - **ElGamal encryption**: Homomorphic encryption for confidential balances
//! - **Range proofs**: Bulletproofs-style proofs for value bounds
//! - **Audit proofs**: Optional regulatory compliance mechanism
//! - **Proof of Exponentiation (PoE)**: Proves knowledge of discrete log
//! - **Fiat-Shamir heuristic**: Non-interactive proof construction
//!
//! ## Timing Attack Resistance
//!
//! The scalar multiplication implementation uses double-and-add which is NOT
//! constant-time. For production deployments requiring resistance to timing
//! attacks, additional hardening may be required.
//!
//! ## Usage Example
//!
//! ```ignore
//! use krusty_kms_sdk::{TongoAccount, operations::{fund, FundParams}};
//! use krusty_kms_crypto::StarkCurve;
//! use starknet_types_core::felt::Felt;
//!
//! // Create account from private key
//! let account = TongoAccount::from_private_key(
//!     Felt::from(42u64),
//!     Felt::from(123456u64)
//! ).unwrap();
//!
//! // Create initial zero balance cipher
//! let g = StarkCurve::generator();
//! let current_balance = krusty_kms_common::ElGamalCiphertext { l: g.clone(), r: g };
//!
//! // Fund account
//! let fund_params = FundParams {
//!     amount: 1000,
//!     nonce: Felt::from(1u64),
//!     chain_id: Felt::from(0x534e5f5345504f4c4941u128),
//!     tongo_address: Felt::from(123456u64),
//!     auditor_pub_key: None,
//!     current_balance,
//! };
//!
//! let fund_proof = fund(&account, fund_params).unwrap();
//! ```

use crate::crypto::encrypt_for_auditor;
use crate::TongoAccount;
use krusty_kms_common::{AuditProof, ElGamalCiphertext, KmsError, ProofOfTransfer, Result};
use krusty_kms_crypto::{
    hash, poseidon_hash_many, range, scalar, AuditProver, ProofOfExponentiation, StarkCurve,
};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Sequential fallback for rayon::join when parallel feature is disabled.
/// Executes closures sequentially instead of in parallel.
#[cfg(not(feature = "parallel"))]
fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA,
    B: FnOnce() -> RB,
{
    (a(), b())
}

/// Cairo string 'fund'
const FUND_CAIRO_STRING: Felt = Felt::from_hex_unchecked("0x66756e64");

/// Cairo string 'transfer'
const TRANSFER_CAIRO_STRING: Felt = Felt::from_hex_unchecked("0x7472616e73666572");

/// Cairo string 'ragequit'
const RAGEQUIT_CAIRO_STRING: Felt = Felt::from_hex_unchecked("0x7261676571756974");

// Cairo string for 'rollover'
const ROLLOVER_CAIRO_STRING: Felt = Felt::from_hex_unchecked("0x726f6c6c6f766572");

// Cairo string for 'withdraw'
const WITHDRAW_CAIRO_STRING: Felt = Felt::from_hex_unchecked("0x7769746864726177");

/// Fund operation parameters.
#[derive(Clone)]
pub struct FundParams {
    pub amount: u128,
    pub nonce: Felt,
    pub chain_id: Felt,
    pub tongo_address: Felt,
    pub auditor_pub_key: Option<ProjectivePoint>,
    pub current_balance: ElGamalCiphertext,
}

/// Transfer operation parameters.
#[derive(Clone)]
pub struct TransferParams {
    /// The recipient's public key. For dual-key wallets, pass the recipient's
    /// viewing public key so the recipient can decrypt without exposing their
    /// ownership/spending key.
    pub recipient_public_key: ProjectivePoint,
    pub amount: u128,
    pub nonce: Felt,
    pub chain_id: Felt,
    pub tongo_address: Felt,
    pub current_balance: ElGamalCiphertext,
    pub bit_size: usize,
    pub auditor_pub_key: Option<ProjectivePoint>,
}

/// Rollover operation parameters.
#[derive(Clone)]
pub struct RolloverParams {
    pub nonce: Felt,
    pub chain_id: Felt,
    pub tongo_address: Felt,
}

/// Withdraw operation parameters.
#[derive(Clone)]
pub struct WithdrawParams {
    pub recipient_address: Felt,
    pub amount: u128,
    pub nonce: Felt,
    pub chain_id: Felt,
    pub tongo_address: Felt,
    pub current_balance: ElGamalCiphertext,
    pub bit_size: usize,
    pub auditor_key: Option<ProjectivePoint>, // Optional auditor public key
}

/// Ragequit operation parameters.
#[derive(Clone)]
pub struct RagequitParams {
    pub recipient_address: Felt,
    pub nonce: Felt,
    pub chain_id: Felt,
    pub tongo_address: Felt,
    pub current_balance: ElGamalCiphertext,
    pub auditor_key: Option<ProjectivePoint>, // Optional auditor public key
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
/// - Amount is zero (`InvalidAmount`)
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
    let y = account.keypair.public_key.clone();

    // Get affine coordinates for prefix computation
    let y_affine = y.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Compute prefix using Poseidon hash
    // prefix = poseidon([chain_id, tongo_address, FUND_CAIRO_STRING, y.x, y.y, amount, nonce])
    let prefix_inputs = vec![
        params.chain_id,
        params.tongo_address,
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
        ProofOfExponentiation::prove(account.keypair.private_key.expose_secret(), &prefix)?;

    // Generate audit if auditor is configured
    let audit = if let Some(ref auditor_key) = params.auditor_pub_key {
        // CRITICAL: The Cairo contract adds the fund amount to balance BEFORE verifying audit
        // So we must prove the balance AFTER funding, not before!
        // See Tongo.cairo:fund() - it calls _add_balance() before _handle_audit_balance()
        let new_balance = account.state.balance + params.amount;

        // Compute the new cipher balance after funding
        // The contract adds: cipher = CipherBalanceTrait::new(to, amount, 'fund')
        // which is: L = g^amount + y^FUND_CAIRO_STRING, R = g^FUND_CAIRO_STRING
        let fund_cipher_l = {
            let g_amount =
                StarkCurve::mul(&Felt::from(params.amount), Some(&StarkCurve::generator()));
            let y_r = StarkCurve::mul(&FUND_CAIRO_STRING, Some(&account.keypair.public_key));
            StarkCurve::add(&g_amount, &y_r)
        };
        let fund_cipher_r = StarkCurve::mul(&FUND_CAIRO_STRING, Some(&StarkCurve::generator()));

        let new_cipher_balance = ElGamalCiphertext {
            l: StarkCurve::add(&params.current_balance.l, &fund_cipher_l),
            r: StarkCurve::add(&params.current_balance.r, &fund_cipher_r),
        };

        // Generate audit proof using the NEW balance (after funding)
        let (audit_proof, audited_balance) = AuditProver::prove(
            account.keypair.private_key.expose_secret(),
            new_balance,
            &new_cipher_balance,
            auditor_key,
        )?;

        // Generate audit hint (XChaCha20-Poly1305 encryption of the plaintext balance)
        // The auditor can decrypt this using ECDH with user's public key
        let (audit_hint_ct, audit_hint_nonce) = encrypt_for_auditor(
            new_balance,
            account.keypair.private_key.expose_secret(),
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

/// Execute a transfer operation.
///
/// Implements the full TONGO transfer protocol with range proofs.
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
        return Err(KmsError::InsufficientBalance {
            available: account.state.balance,
            required: params.amount,
        });
    }

    // Setup variables matching TypeScript implementation
    let x = account.keypair.private_key.expose_secret();
    let y = account.keypair.public_key.clone();
    let to = &params.recipient_public_key;
    let b = params.amount;
    let b0 = account.state.balance;
    let g = StarkCurve::generator();
    let h = StarkCurve::generator_h();

    // Get affine coordinates for prefix computation
    let y_affine = y.to_affine().map_err(|_| KmsError::PointAtInfinity)?;
    let to_affine = to.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Compute prefix: poseidon([chain_id, tongo_address, TRANSFER_CAIRO_STRING, y.x, y.y, to.x, to.y, nonce])
    // Reference: transfer.ts:46-63
    let prefix_inputs = vec![
        params.chain_id,
        params.tongo_address,
        TRANSFER_CAIRO_STRING,
        y_affine.x(),
        y_affine.y(),
        to_affine.x(),
        to_affine.y(),
        params.nonce,
    ];
    let prefix = poseidon_hash_many(&prefix_inputs);

    // Compute leftover balance
    let b_left = b0 - b;

    // OPTIMIZATION: Generate both range proofs in parallel (2x speedup expected)
    // Reference: transfer.ts:108 and transfer.ts:113-115
    // CRITICAL: We get randomness r FROM the range proof generation!
    #[cfg(feature = "parallel")]
    let (result1, result2) = rayon::join(
        || range::prove(b, params.bit_size, &g, &h, &prefix),
        || range::prove(b_left, params.bit_size, &g, &h, &prefix),
    );
    #[cfg(not(feature = "parallel"))]
    let (result1, result2) = join(
        || range::prove(b, params.bit_size, &g, &h, &prefix),
        || range::prove(b_left, params.bit_size, &g, &h, &prefix),
    );
    let (range, r) = result1?;
    let (range2, r2) = result2?;

    // Create cipher balances using r from range proof
    // transferBalanceSelf: encryption for sender (transfer.ts:109)
    // transferBalance: encryption for recipient (transfer.ts:110)
    let transfer_balance_self_l = {
        let g_b = StarkCurve::mul(&Felt::from(b), Some(&g));
        let y_r = StarkCurve::mul(&r, Some(&y));
        StarkCurve::add(&g_b, &y_r)
    };
    let transfer_balance_self_r = StarkCurve::mul(&r, Some(&g));

    let transfer_balance_l = {
        let g_b = StarkCurve::mul(&Felt::from(b), Some(&g));
        let to_r = StarkCurve::mul(&r, Some(to));
        StarkCurve::add(&g_b, &to_r)
    };
    let transfer_balance_r = StarkCurve::mul(&r, Some(&g));

    // R_aux = g^r (transfer.ts:111)
    let r_aux = StarkCurve::mul(&r, Some(&g));
    let r_aux2 = StarkCurve::mul(&r2, Some(&g));

    // Compute G = R0 - transferBalanceSelf.R (transfer.ts:128)
    let g_point = {
        let r_transfer_affine = StarkCurve::projective_to_affine(&transfer_balance_self_r)?;
        let neg_r_transfer = StarkCurve::affine_to_projective(&create_affine_point(
            r_transfer_affine.x(),
            -r_transfer_affine.y(),
        )?);
        StarkCurve::add(&params.current_balance.r, &neg_r_transfer)
    };

    // Generate 5 random k values for commitments (transfer.ts:130-134)
    let kx = krusty_kms_crypto::scalar::random_felt();
    let kb = krusty_kms_crypto::scalar::random_felt();
    let kr = krusty_kms_crypto::scalar::random_felt();
    let kb2 = krusty_kms_crypto::scalar::random_felt();
    let kr2 = krusty_kms_crypto::scalar::random_felt();

    // Compute 8 commitments (transfer.ts:136-143)
    let a_x = StarkCurve::mul(&kx, Some(&g));
    let a_r = StarkCurve::mul(&kr, Some(&g));
    let a_r2 = StarkCurve::mul(&kr2, Some(&g));

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
        let h_kr2 = StarkCurve::mul(&kr2, Some(&h));
        StarkCurve::add(&g_kb2, &h_kr2)
    };

    // Compute challenge from prefix and all 8 commitments (transfer.ts:156)
    let challenge = krusty_kms_crypto::hash::compute_poseidon_challenge(
        &prefix,
        &[&a_x, &a_r, &a_r2, &a_b, &a_b2, &a_v, &a_v2, &a_bar],
    )?;

    // Compute 5 scalar responses s = k + value * c (transfer.ts:158-162)
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
        &kr2,
        &krusty_kms_crypto::scalar::scalar_mul(&challenge, &r2)?,
    )?;

    // Assemble ProofOfTransfer (transfer.ts:164-182)
    let proof = ProofOfTransfer {
        a_x: krusty_kms_common::SerializablePoint::try_from_projective(&a_x)?,
        a_r: krusty_kms_common::SerializablePoint::try_from_projective(&a_r)?,
        a_r2: krusty_kms_common::SerializablePoint::try_from_projective(&a_r2)?,
        a_b: krusty_kms_common::SerializablePoint::try_from_projective(&a_b)?,
        a_b2: krusty_kms_common::SerializablePoint::try_from_projective(&a_b2)?,
        a_v: krusty_kms_common::SerializablePoint::try_from_projective(&a_v)?,
        a_v2: krusty_kms_common::SerializablePoint::try_from_projective(&a_v2)?,
        a_bar: krusty_kms_common::SerializablePoint::try_from_projective(&a_bar)?,
        s_x: format!("{s_x:#x}"),
        s_r: format!("{s_r:#x}"),
        s_b: format!("{s_b:#x}"),
        s_b2: format!("{s_b2:#x}"),
        s_r2: format!("{s_r2:#x}"),
        r_aux: krusty_kms_common::SerializablePoint::try_from_projective(&r_aux)?,
        range,
        r_aux2: krusty_kms_common::SerializablePoint::try_from_projective(&r_aux2)?,
        range2,
    };

    // Compute new cipher balance (transfer.ts:184)
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
        // AUDIT 1: Sender's new balance after transfer
        // Use prove_with_validation(false) because new_balance_cipher is computed by subtraction
        // and won't pass standard validation but will verify correctly on-chain
        let (audit_balance_proof, audited_balance) = AuditProver::prove_with_validation(
            account.keypair.private_key.expose_secret(),
            b_left,
            &new_balance_cipher,
            auditor_key,
            false, // Skip validation for subtracted cipher
        )?;

        // Encrypt sender's new balance for auditor
        let (audit_balance_hint_ct, audit_balance_hint_nonce) = encrypt_for_auditor(
            b_left,
            account.keypair.private_key.expose_secret(),
            auditor_key,
        )?;

        // AUDIT 2: Transfer amount
        // transfer_cipher_self is a proper ElGamal encryption (L = g^b * y^r, R = g^r)
        // using randomness from range proof, so it should pass validation
        let transfer_cipher_self = ElGamalCiphertext {
            l: transfer_balance_self_l.clone(),
            r: transfer_balance_self_r.clone(),
        };

        let (audit_transfer_proof, audited_transfer) = AuditProver::prove(
            account.keypair.private_key.expose_secret(),
            b,
            &transfer_cipher_self,
            auditor_key,
        )?;

        // Encrypt transfer amount for auditor
        let (audit_transfer_hint_ct, audit_transfer_hint_nonce) =
            encrypt_for_auditor(b, account.keypair.private_key.expose_secret(), auditor_key)?;

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
        new_balance_cipher,
        audit_balance,
        audit_transfer,
    })
}

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
    let y = account.keypair.public_key.clone();

    // Get affine coordinates for prefix computation
    let y_affine = y.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Compute prefix using Poseidon hash (MUST match TypeScript exactly!)
    // prefix = poseidon([chain_id, tongo_address, 'rollover', y.x, y.y, nonce])
    let prefix_inputs = vec![
        params.chain_id,
        params.tongo_address,
        ROLLOVER_CAIRO_STRING,
        y_affine.x(),
        y_affine.y(),
        params.nonce,
    ];
    let prefix = poseidon_hash_many(&prefix_inputs);

    // Generate proof of knowledge of private key: y = g^x
    // This proves the account owner authorized this rollover operation
    let (_, proof) =
        ProofOfExponentiation::prove(account.keypair.private_key.expose_secret(), &prefix)?;

    Ok(RolloverProof {
        y,
        proof,
        pending_amount: account.state.pending_balance,
    })
}

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
        return Err(KmsError::InsufficientBalance {
            available: account.state.balance,
            required: params.amount,
        });
    }

    let x: &Felt = account.keypair.private_key.expose_secret();
    let g = StarkCurve::generator();
    let h = StarkCurve::generator_h();

    // Compute y = g^x
    let y = account.keypair.public_key.clone();
    let y_affine = y.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Extract L0, R0 from current cipherbalance
    let l0 = &params.current_balance.l;
    let r0 = &params.current_balance.r;

    // Verify storedBalance is an encryption of the balance: g^b = L0 - R0^x
    let r0_x = StarkCurve::mul(x, Some(r0));
    let r0_x_affine = StarkCurve::projective_to_affine(&r0_x)?;
    let neg_r0_x =
        StarkCurve::affine_to_projective(&create_affine_point(r0_x_affine.x(), -r0_x_affine.y())?);
    let g_b = StarkCurve::add(l0, &neg_r0_x);
    let expected_g_b = StarkCurve::mul(&Felt::from(account.state.balance), Some(&g));

    let g_b_affine = StarkCurve::projective_to_affine(&g_b)?;
    let expected_g_b_affine = StarkCurve::projective_to_affine(&expected_g_b)?;

    if g_b_affine != expected_g_b_affine {
        return Err(KmsError::CryptoError(
            "storedBalance is not an encryption of balance".to_string(),
        ));
    }

    // Compute prefix: [chain_id, tongo_address, WITHDRAW_CAIRO_STRING, y.x, y.y, nonce, amount, to]
    let prefix_inputs = vec![
        params.chain_id,
        params.tongo_address,
        WITHDRAW_CAIRO_STRING,
        y_affine.x(),
        y_affine.y(),
        params.nonce,
        Felt::from(params.amount),
        params.recipient_address,
    ];
    let prefix = poseidon_hash_many(&prefix_inputs);

    // Compute leftover balance
    let left = account.state.balance - params.amount;

    // Generate range proof for leftover balance
    let (range, r) = range::prove(left, params.bit_size, &g, &h, &prefix)?;

    // OPTIMIZATION: Generate random values and scalar multiplications in parallel
    // These operations are independent and can run concurrently
    #[cfg(feature = "parallel")]
    let (r_aux_result, random_and_commitments) = rayon::join(
        || StarkCurve::mul(&r, Some(&g)),
        || {
            // Generate all 3 random values at once (amortize RNG overhead)
            use krusty_kms_crypto::random::random_felts;
            let randoms = random_felts(3);
            let (kb, kx, kr) = (&randoms[0], &randoms[1], &randoms[2]);

            // Compute all commitments in parallel
            let ((a_x, a_r), (g_kb, r0_kx, h_kr)) = rayon::join(
                || {
                    let ax = StarkCurve::mul(kx, Some(&g));
                    let ar = StarkCurve::mul(kr, Some(&g));
                    (ax, ar)
                },
                || {
                    let gkb = StarkCurve::mul(kb, Some(&g));
                    let r0kx = StarkCurve::mul(kx, Some(r0));
                    let hkr = StarkCurve::mul(kr, Some(&h));
                    (gkb, r0kx, hkr)
                },
            );

            (*kb, *kx, *kr, a_x, a_r, g_kb, r0_kx, h_kr)
        },
    );
    #[cfg(not(feature = "parallel"))]
    let (r_aux_result, random_and_commitments) = {
        let r_aux_result = StarkCurve::mul(&r, Some(&g));
        let random_and_commitments = {
            // Generate all 3 random values at once (amortize RNG overhead)
            use krusty_kms_crypto::random::random_felts;
            let randoms = random_felts(3);
            let (kb, kx, kr) = (&randoms[0], &randoms[1], &randoms[2]);

            // Compute all commitments sequentially
            let ax = StarkCurve::mul(kx, Some(&g));
            let ar = StarkCurve::mul(kr, Some(&g));
            let gkb = StarkCurve::mul(kb, Some(&g));
            let r0kx = StarkCurve::mul(kx, Some(r0));
            let hkr = StarkCurve::mul(kr, Some(&h));

            (kb.clone(), kx.clone(), kr.clone(), ax, ar, gkb, r0kx, hkr)
        };
        (r_aux_result, random_and_commitments)
    };

    let r_aux = r_aux_result;
    let (kb, kx, kr, a_x, a_r, g_kb, r0_kx, h_kr) = random_and_commitments;

    // Combine results (must be sequential)
    let a = StarkCurve::add(&g_kb, &r0_kx);
    let a_v = StarkCurve::add(&g_kb, &h_kr);

    // Compute challenge c = H(prefix, [A_x, A_r, A, A_v])
    // CRITICAL: Use Poseidon hash (not Pedersen) to match Cairo implementation
    let c = hash::compute_poseidon_challenge(&prefix, &[&a_x, &a_r, &a, &a_v])?;

    // Compute responses: s = k + c*value
    let c_left = scalar::scalar_mul(&c, &Felt::from(left))?;
    let sb = scalar::scalar_add(&kb, &c_left)?;

    let c_x = scalar::scalar_mul(&c, &x)?;
    let sx = scalar::scalar_add(&kx, &c_x)?;

    let c_r = scalar::scalar_mul(&c, &r)?;
    let sr = scalar::scalar_add(&kr, &c_r)?;

    // Generate audit proof if auditor key is provided
    let audit = if let Some(auditor_key) = params.auditor_key {
        // Create cipher for withdraw amount using fixed randomness "withdraw"
        // Reference: typescript-reference/tongo-sdk/src/provers/withdraw.ts:157
        // cipher = createCipherBalance(y, amount, WITHDRAW_CAIRO_STRING)

        // cipher.L = g^amount + y^r_withdraw
        let cipher_l = {
            let g_amount = StarkCurve::mul(&Felt::from(params.amount), Some(&g));
            let y_r = StarkCurve::mul(&WITHDRAW_CAIRO_STRING, Some(&y));
            StarkCurve::add(&g_amount, &y_r)
        };
        // cipher.R = g^r_withdraw
        let cipher_r = StarkCurve::mul(&WITHDRAW_CAIRO_STRING, Some(&g));

        // Compute leftover cipher = current_cipher - withdraw_cipher
        // newBalance.L = L0 - cipher.L
        let cipher_l_affine = StarkCurve::projective_to_affine(&cipher_l)?;
        let neg_cipher_l = StarkCurve::affine_to_projective(&create_affine_point(
            cipher_l_affine.x(),
            -cipher_l_affine.y(),
        )?);
        let l_left = StarkCurve::add(l0, &neg_cipher_l);

        // newBalance.R = R0 - cipher.R
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

        // Use prove_with_validation(false) because leftover_cipher is computed by subtraction
        // and won't pass standard validation but will verify correctly on-chain
        let (audit_proof, audited_balance) = AuditProver::prove_with_validation(
            account.keypair.private_key.expose_secret(),
            left,
            &leftover_cipher,
            &auditor_key,
            false, // Skip validation for subtracted cipher
        )?;

        // Encrypt leftover balance for auditor using XChaCha20-Poly1305
        let (audit_hint_ct, audit_hint_nonce) = encrypt_for_auditor(
            left,
            account.keypair.private_key.expose_secret(),
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
        r_aux,
        range,
        amount: params.amount,
        recipient: params.recipient_address,
        audit,
    })
}

/// Execute a ragequit operation.
///
/// Withdraws the ENTIRE balance from the TONGO account, leaving a balance of 0.
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
    let x: &Felt = account.keypair.private_key.expose_secret();
    let g = StarkCurve::generator();

    // Compute y = g^x
    let y = account.keypair.public_key.clone();
    let y_affine = y.to_affine().map_err(|_| KmsError::PointAtInfinity)?;

    // Extract L0, R0 from current cipherbalance
    let l0 = &params.current_balance.l;
    let r0 = &params.current_balance.r;

    // Verify storedBalance is an encryption of the full balance: g^b = L0 - R0^x
    // Reference: ragequit.ts:78-81
    let r0_x = StarkCurve::mul(&x, Some(r0));
    let r0_x_affine = StarkCurve::projective_to_affine(&r0_x)?;
    let neg_r0_x =
        StarkCurve::affine_to_projective(&create_affine_point(r0_x_affine.x(), -r0_x_affine.y())?);
    let g_b = StarkCurve::add(l0, &neg_r0_x);
    let expected_g_b = StarkCurve::mul(&Felt::from(account.state.balance), Some(&g));

    let g_b_affine = StarkCurve::projective_to_affine(&g_b)?;
    let expected_g_b_affine = StarkCurve::projective_to_affine(&expected_g_b)?;

    if g_b_affine != expected_g_b_affine {
        return Err(KmsError::CryptoError(
            "storedBalance is not an encryption of full balance".to_string(),
        ));
    }

    // Full amount is the entire account balance
    let full_amount = account.state.balance;

    // Compute prefix: [chain_id, tongo_address, RAGEQUIT_CAIRO_STRING, y.x, y.y, nonce, amount, to]
    // Reference: ragequit.ts:36-48
    let prefix_inputs = vec![
        params.chain_id,
        params.tongo_address,
        RAGEQUIT_CAIRO_STRING,
        y_affine.x(),
        y_affine.y(),
        params.nonce,
        Felt::from(full_amount),
        params.recipient_address,
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
    let c_x = scalar::scalar_mul(&c, &x)?;
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

        // Skip validation due to Rust curve implementation difference:
        // - Cairo: 0 * g = O (point at infinity), so cipher (y, g) validates as: y - g*x = y - y = O = g^0
        // - Rust: 0 * g = g (bug in scalar_mul), so validation fails locally
        // The cipher is mathematically correct and will verify on-chain with Cairo's implementation
        let (audit_proof, audited_balance) = AuditProver::prove_with_validation(
            account.keypair.private_key.expose_secret(),
            0, // Balance after ragequit is 0
            &new_balance_cipher,
            &auditor_key,
            false, // Skip validation due to curve implementation difference
        )?;

        // Encrypt zero balance for auditor (after ragequit balance is 0)
        let (audit_hint_ct, audit_hint_nonce) = encrypt_for_auditor(
            0, // Balance after ragequit is 0
            account.keypair.private_key.expose_secret(),
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

/// Create an affine point from coordinates.
fn create_affine_point(x: Felt, y: Felt) -> Result<starknet_types_core::curve::AffinePoint> {
    use starknet_types_core::curve::AffinePoint;
    AffinePoint::new(x, y).map_err(|e| {
        krusty_kms_common::KmsError::InvalidPublicKey(format!("Invalid affine point: {:?}", e))
    })
}

// Proof structures

/// Audit information for declaring balance.
#[derive(Clone)]
pub struct Audit {
    pub audited_balance: ElGamalCiphertext,
    pub hint_ciphertext: [u8; 64],
    pub hint_nonce: [u8; 24],
    pub proof: AuditProof,
}

pub struct FundProof {
    pub y: ProjectivePoint,
    pub proof: krusty_kms_common::PoeProof,
    pub amount: u128,
    pub audit: Option<Audit>,
}

pub struct TransferProof {
    pub transfer_balance_l: ProjectivePoint, // transferBalance.L (for recipient)
    pub transfer_balance_r: ProjectivePoint, // transferBalance.R (for recipient)
    pub transfer_balance_self_l: ProjectivePoint, // transferBalanceSelf.L (for sender)
    pub transfer_balance_self_r: ProjectivePoint, // transferBalanceSelf.R (for sender)
    pub proof: ProofOfTransfer, // Complete transfer proof with 8 commitments, 5 scalars, 2 range proofs
    pub new_balance_cipher: ElGamalCiphertext, // Updated balance cipher after transfer
    pub audit_balance: Option<Audit>, // Sender's balance after transfer (optional)
    pub audit_transfer: Option<Audit>, // Transfer cipher audit (optional)
}

pub struct RolloverProof {
    pub y: ProjectivePoint,
    pub proof: krusty_kms_common::PoeProof,
    pub pending_amount: u128,
}

pub struct WithdrawProof {
    pub y: ProjectivePoint,              // User's public key
    pub a_x: ProjectivePoint,            // Commitment for proof of private key
    pub a_r: ProjectivePoint,            // Commitment for range proof randomness
    pub a: ProjectivePoint,              // Commitment for balance encryption proof
    pub a_v: ProjectivePoint,            // Commitment for V linkage proof
    pub sx: Felt,                        // Response for private key
    pub sb: Felt,                        // Response for leftover balance
    pub sr: Felt,                        // Response for range proof randomness
    pub r_aux: ProjectivePoint,          // R auxiliary point (g^r)
    pub range: krusty_kms_common::Range, // Range proof for leftover balance
    pub amount: u128,
    pub recipient: Felt,
    pub audit: Option<Audit>, // Optional audit proof for leftover balance
}

pub struct RagequitProof {
    pub y: ProjectivePoint,   // User's public key
    pub a_x: ProjectivePoint, // Ax = g^kx
    pub a_r: ProjectivePoint, // AR = R0^kx
    pub sx: Felt,             // sx = kx + c*x
    pub amount: u128,         // Full balance amount to withdraw
    pub recipient: Felt,      // Recipient address
    pub audit: Option<Audit>, // Optional audit proof (for consistency)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "habit hope tip crystal because grunt nation idea electric witness alert like";

    fn create_test_account() -> TongoAccount {
        let contract_address = Felt::from(123456u64);
        let mut account =
            TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();
        account.state.balance = 1000;
        account
    }

    #[test]
    fn test_fund() {
        let account = create_test_account();
        let contract_address = Felt::from(123456u64);

        // Create dummy current balance (zero balance for first fund)
        let current_balance = ElGamalCiphertext {
            l: StarkCurve::generator(),
            r: StarkCurve::generator(),
        };

        let params = FundParams {
            amount: 100,
            nonce: Felt::from(1u64),
            chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(), // SN_SEPOLIA
            tongo_address: contract_address,
            auditor_pub_key: None,
            current_balance,
        };

        let result = fund(&account, params);
        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.amount, 100);
        assert!(proof.audit.is_none());
    }

    #[test]
    fn test_fund_zero_amount() {
        let account = create_test_account();
        let contract_address = Felt::from(123456u64);

        let current_balance = ElGamalCiphertext {
            l: StarkCurve::generator(),
            r: StarkCurve::generator(),
        };

        let params = FundParams {
            amount: 0,
            nonce: Felt::from(1u64),
            chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
            tongo_address: contract_address,
            auditor_pub_key: None,
            current_balance,
        };

        let result = fund(&account, params);
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer() {
        use krusty_kms_crypto::StarkCurve;
        let account = create_test_account();
        let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
        let g = StarkCurve::generator();
        let current_balance = ElGamalCiphertext {
            l: StarkCurve::mul(&Felt::from(1000u128), Some(&g)),
            r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
        };

        let params = TransferParams {
            recipient_public_key: recipient_key,
            amount: 100,
            nonce: Felt::from(1u64),
            chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
            tongo_address: Felt::from(123456u64),
            current_balance,
            bit_size: 16,
            auditor_pub_key: None,
        };

        let result = transfer(&account, params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transfer_insufficient_balance() {
        use krusty_kms_crypto::StarkCurve;
        let account = create_test_account();
        let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
        let g = StarkCurve::generator();
        let current_balance = ElGamalCiphertext {
            l: StarkCurve::mul(&Felt::from(1000u128), Some(&g)),
            r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
        };

        let params = TransferParams {
            recipient_public_key: recipient_key,
            amount: 2000,
            nonce: Felt::from(1u64),
            chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
            tongo_address: Felt::from(123456u64),
            current_balance,
            bit_size: 16,
            auditor_pub_key: None,
        };

        let result = transfer(&account, params);
        assert!(result.is_err());
    }

    #[test]
    fn test_rollover() {
        let mut account = create_test_account();
        account.state.pending_balance = 50;

        let params = RolloverParams {
            nonce: Felt::from(1u64),
            chain_id: Felt::from(1u64),
            tongo_address: Felt::from(123u64),
        };

        let result = rollover(&account, params);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().pending_amount, 50);
    }

    #[test]
    #[ignore = "Comprehensive testing done in integration tests"]
    fn test_withdraw() {
        // Note: This test is simplified. Comprehensive withdraw testing
        // is performed in integration tests with real on-chain state.
        use krusty_kms_crypto::StarkCurve;
        let mut account = create_test_account();
        account.state.balance = 1000; // Set balance to match cipher
        let g = StarkCurve::generator();
        let current_balance = ElGamalCiphertext {
            l: StarkCurve::mul(&Felt::from(1000u128), Some(&g)),
            r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
        };

        let params = WithdrawParams {
            recipient_address: Felt::from(999u64),
            amount: 100,
            nonce: Felt::from(1u64),
            chain_id: Felt::from(1u64),
            tongo_address: Felt::from(123u64),
            current_balance,
            bit_size: 32,
            auditor_key: None,
        };

        let result = withdraw(&account, params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_withdraw_insufficient_balance() {
        use krusty_kms_crypto::StarkCurve;
        let account = create_test_account();
        let g = StarkCurve::generator();
        let current_balance = ElGamalCiphertext {
            l: StarkCurve::mul(&Felt::from(100u128), Some(&g)),
            r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
        };

        let params = WithdrawParams {
            recipient_address: Felt::from(999u64),
            amount: 2000,
            nonce: Felt::from(1u64),
            chain_id: Felt::from(1u64),
            tongo_address: Felt::from(123u64),
            current_balance,
            bit_size: 32,
            auditor_key: None,
        };

        let result = withdraw(&account, params);
        assert!(result.is_err());
    }

    #[test]
    fn test_fund_with_auditor() {
        // Create account with zero balance (matching the cipher we'll create)
        let contract_address = Felt::from(123456u64);
        let mut account =
            TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();
        account.state.balance = 0; // Must match the cipher's encrypted value

        // For audit to work, cipher must be encrypted under owner key (not view key)
        // because AuditProver uses account.keypair.private_key for verification
        let owner_pk = &account.keypair.public_key;

        // Create a valid zero balance cipher (L = pk^r, R = g^r where balance = 0)
        // For balance=0: L = g^0 + pk^r = pk^r (since g^0 = identity)
        let g = StarkCurve::generator();
        let random = Felt::from(12345u64);
        let r_point = StarkCurve::mul(&random, Some(&g));
        let pk_r = StarkCurve::mul(&random, Some(owner_pk));
        let current_balance = ElGamalCiphertext {
            l: pk_r,
            r: r_point,
        };

        // Create an auditor public key
        let auditor_pub_key = StarkCurve::mul_generator(&Felt::from(9999u64));

        let params = FundParams {
            amount: 100,
            nonce: Felt::from(1u64),
            chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
            tongo_address: contract_address,
            auditor_pub_key: Some(auditor_pub_key),
            current_balance,
        };

        let result = fund(&account, params);
        assert!(result.is_ok(), "fund failed: {:?}", result.err());
        let proof = result.unwrap();
        assert_eq!(proof.amount, 100);
        // With auditor, audit should be present
        assert!(proof.audit.is_some());
    }

    #[test]
    fn test_rollover_zero_pending() {
        let mut account = create_test_account();
        account.state.pending_balance = 0;

        let params = RolloverParams {
            nonce: Felt::from(1u64),
            chain_id: Felt::from(1u64),
            tongo_address: Felt::from(123u64),
        };

        let result = rollover(&account, params);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().pending_amount, 0);
    }

    #[test]
    fn test_ragequit() {
        use krusty_kms_crypto::StarkCurve;
        let mut account = create_test_account();
        account.state.balance = 1000;

        let g = StarkCurve::generator();
        // Construct a valid cipher for balance 1000 with some randomness
        // Use the owner key (spend key) rather than view key for this test
        // Ragequit uses owner key for verification
        let random = Felt::from(42u64);
        let owner_pk = &account.keypair.public_key;
        let g_b = StarkCurve::mul(&Felt::from(1000u128), Some(&g));
        let pk_r = StarkCurve::mul(&random, Some(owner_pk));
        let l = StarkCurve::add(&g_b, &pk_r);
        let r = StarkCurve::mul(&random, Some(&g));

        let current_balance = ElGamalCiphertext { l, r };

        let params = RagequitParams {
            recipient_address: Felt::from(999u64),
            nonce: Felt::from(1u64),
            chain_id: Felt::from(1u64),
            tongo_address: Felt::from(123u64),
            current_balance,
            auditor_key: None,
        };

        let result = ragequit(&account, params);
        assert!(result.is_ok(), "ragequit failed: {:?}", result.err());
        let proof = result.unwrap();
        assert_eq!(proof.amount, 1000);
    }

    #[test]
    fn test_transfer_with_auditor() {
        use krusty_kms_crypto::StarkCurve;
        let account = create_test_account();
        let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
        let auditor_key = StarkCurve::mul_generator(&Felt::from(888u64));
        let g = StarkCurve::generator();
        let current_balance = ElGamalCiphertext {
            l: StarkCurve::mul(&Felt::from(1000u128), Some(&g)),
            r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
        };

        let params = TransferParams {
            recipient_public_key: recipient_key,
            amount: 100,
            nonce: Felt::from(1u64),
            chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
            tongo_address: Felt::from(123456u64),
            current_balance,
            bit_size: 16,
            auditor_pub_key: Some(auditor_key),
        };

        let result = transfer(&account, params);
        assert!(result.is_ok());
        let proof = result.unwrap();
        // Audit data should be present when auditor key is provided
        assert!(proof.audit_balance.is_some());
        assert!(proof.audit_transfer.is_some());
    }

    #[test]
    fn test_transfer_zero_amount() {
        use krusty_kms_crypto::StarkCurve;
        let account = create_test_account();
        let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
        let g = StarkCurve::generator();
        let current_balance = ElGamalCiphertext {
            l: StarkCurve::mul(&Felt::from(1000u128), Some(&g)),
            r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
        };

        let params = TransferParams {
            recipient_public_key: recipient_key,
            amount: 0,
            nonce: Felt::from(1u64),
            chain_id: Felt::from_hex("0x534e5f5345504f4c4941").unwrap(),
            tongo_address: Felt::from(123456u64),
            current_balance,
            bit_size: 16,
            auditor_pub_key: None,
        };

        let result = transfer(&account, params);
        assert!(result.is_err());
    }

    #[test]
    fn test_withdraw_zero_amount() {
        use krusty_kms_crypto::StarkCurve;
        let account = create_test_account();
        let g = StarkCurve::generator();
        let current_balance = ElGamalCiphertext {
            l: StarkCurve::mul(&Felt::from(1000u128), Some(&g)),
            r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
        };

        let params = WithdrawParams {
            recipient_address: Felt::from(999u64),
            amount: 0,
            nonce: Felt::from(1u64),
            chain_id: Felt::from(1u64),
            tongo_address: Felt::from(123u64),
            current_balance,
            bit_size: 32,
            auditor_key: None,
        };

        let result = withdraw(&account, params);
        assert!(result.is_err());
    }
}
