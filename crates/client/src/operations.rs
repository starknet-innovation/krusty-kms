//! Tongo operation calldata builders.
//!
//! This module constructs `Call` structures for Tongo operations that can be
//! executed via starknet-rs accounts. It serializes operation proofs into Cairo
//! calldata format.

use crate::serialization;
use krusty_kms_common::Result;
use krusty_kms_sdk::operations::{
    FundProof, RagequitProof, RolloverProof, TransferProof, WithdrawProof,
};
use starknet_rust::core::types::Call;
use starknet_rust::core::utils::get_selector_from_name;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt as CoreFelt;

// Type aliases for clarity
type StarknetRsFelt = starknet_rust::core::types::Felt;

/// Convert from starknet-types-core Felt to starknet-rs Felt.
#[must_use]
fn core_felt_to_rs(felt: CoreFelt) -> StarknetRsFelt {
    StarknetRsFelt::from_bytes_be(&felt.to_bytes_be())
}

/// Build a Call for the Fund operation.
///
/// This requires two calls:
/// 1. ERC20.approve(tongo_address, amount * rate)
/// 2. Tongo.fund(to, amount, hint, proof, audit)
///
/// # Returns
/// A tuple of (approve_call, fund_call)
///
/// # Cyclomatic Complexity: 2
pub fn build_fund_calls(
    tongo_address: CoreFelt,
    erc20_address: CoreFelt,
    rate: u128,
    proof: &FundProof,
    hint_ciphertext: &[u8; 64],
    hint_nonce: &[u8; 24],
) -> Result<(Call, Call)> {
    // 1. Build ERC20 approve call
    let approve_amount = proof.amount * rate;
    let approve_call = build_erc20_approve(erc20_address, tongo_address, approve_amount)?;

    // 2. Build fund call
    // Calldata: [to.x, to.y, amount, hint (6 felts), proof.Ax, proof.Ay, proof.sx, audit (Option)]
    let mut calldata = Vec::new();

    // Serialize 'to' public key
    let (to_x, to_y) = serialization::serialize_projective_point(&proof.y)?;
    calldata.push(core_felt_to_rs(to_x));
    calldata.push(core_felt_to_rs(to_y));

    // Serialize amount (u128 -> felt)
    calldata.push(core_felt_to_rs(CoreFelt::from(proof.amount)));

    // Serialize hint (AEBalance: 6 felts)
    let hint_felts = serialization::serialize_ae_balance(hint_ciphertext, hint_nonce)?;
    for felt in hint_felts {
        calldata.push(core_felt_to_rs(felt));
    }

    // Serialize proof (PoeProof: 3 felts = Ax, Ay, sx)
    let proof_felts = serialization::serialize_poe_proof(&proof.proof)?;
    for felt in proof_felts {
        calldata.push(core_felt_to_rs(felt));
    }

    // Serialize audit (CairoOption<Audit>)
    if let Some(ref audit) = proof.audit {
        // CairoOption::Some(Audit)
        // Format: [0, audited_balance (4 felts), hint (6 felts), proof (11 felts)]
        calldata.push(core_felt_to_rs(CoreFelt::ZERO)); // Some variant

        // Serialize audited balance (CipherBalance: 4 felts)
        let balance_felts = serialization::serialize_cipher_balance(&audit.audited_balance)?;
        for felt in balance_felts {
            calldata.push(core_felt_to_rs(felt));
        }

        // Serialize audit hint (AEBalance: 6 felts)
        let audit_hint_felts =
            serialization::serialize_ae_balance(&audit.hint_ciphertext, &audit.hint_nonce)?;
        for felt in audit_hint_felts {
            calldata.push(core_felt_to_rs(felt));
        }

        // Serialize audit proof (11 felts)
        let audit_proof_felts = serialization::serialize_audit_proof(&audit.proof)?;
        for felt in audit_proof_felts {
            calldata.push(core_felt_to_rs(felt));
        }
    } else {
        // CairoOption::None
        calldata.push(core_felt_to_rs(CoreFelt::ONE)); // None variant
    }

    let fund_call = Call {
        to: core_felt_to_rs(tongo_address),
        selector: get_selector_from_name("fund")
            .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
        calldata,
    };

    Ok((approve_call, fund_call))
}

/// Build an ERC20 approve call.
///
/// # Cyclomatic Complexity: 1
pub fn build_erc20_approve(
    erc20_address: CoreFelt,
    spender: CoreFelt,
    amount: u128,
) -> Result<Call> {
    // Convert amount to u256 (low, high)
    let (low, high) = serialization::u128_to_u256(amount);

    Ok(Call {
        to: core_felt_to_rs(erc20_address),
        selector: get_selector_from_name("approve")
            .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
        calldata: vec![
            core_felt_to_rs(spender),
            core_felt_to_rs(low),
            core_felt_to_rs(high),
        ],
    })
}

/// Build a Call for the Rollover operation.
///
/// # Cyclomatic Complexity: 1
pub fn build_rollover_call(
    tongo_address: CoreFelt,
    proof: &RolloverProof,
    hint_ciphertext: &[u8; 64],
    hint_nonce: &[u8; 24],
) -> Result<Call> {
    // Calldata: [to.x, to.y, hint (6 felts), proof.Ax, proof.Ay, proof.sx]
    let mut calldata = Vec::new();

    // Serialize 'to' public key
    let (to_x, to_y) = serialization::serialize_projective_point(&proof.y)?;
    calldata.push(core_felt_to_rs(to_x));
    calldata.push(core_felt_to_rs(to_y));

    // Serialize hint
    let hint_felts = serialization::serialize_ae_balance(hint_ciphertext, hint_nonce)?;
    for felt in hint_felts {
        calldata.push(core_felt_to_rs(felt));
    }

    // Serialize proof (ProofOfRollOver: 3 felts = Ax, Ay, sx)
    let proof_felts = serialization::serialize_poe_proof(&proof.proof)?;
    for felt in proof_felts {
        calldata.push(core_felt_to_rs(felt));
    }

    Ok(Call {
        to: core_felt_to_rs(tongo_address),
        selector: get_selector_from_name("rollover")
            .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
        calldata,
    })
}

/// Build a Call for the Withdraw operation.
///
/// Serializes withdraw operation with full proof structure matching contract.
///
/// # Cyclomatic Complexity: 1
pub fn build_withdraw_call(
    tongo_address: CoreFelt,
    proof: &WithdrawProof,
    hint_ciphertext: &[u8; 64],
    hint_nonce: &[u8; 24],
) -> Result<Call> {
    // Calldata structure (matching Cairo Withdraw struct):
    // 1. from: PubKey (2 felts)
    // 2. to: ContractAddress (1 felt)
    // 3. amount: u128 (1 felt)
    // 4. hint: AEBalance (6 felts)
    // 5. auxiliarCipher: CipherBalance (4 felts - V.x, V.y, R_aux.x, R_aux.y)
    // 6. proof: ProofOfWithdraw
    //    - A_x: Point (2 felts)
    //    - A_r: Point (2 felts)
    //    - A: Point (2 felts)
    //    - A_v: Point (2 felts)
    //    - sx: felt (1 felt)
    //    - sb: felt (1 felt)
    //    - sr: felt (1 felt)
    //    - range: Range (variable felts)
    // 7. auditPart: CairoOption<Audit>

    let mut calldata = Vec::new();

    // 1. Serialize 'from' public key
    let (from_x, from_y) = serialization::serialize_projective_point(&proof.y)?;
    calldata.push(core_felt_to_rs(from_x));
    calldata.push(core_felt_to_rs(from_y));

    // 2. Serialize 'to' recipient address
    calldata.push(core_felt_to_rs(proof.recipient));

    // 3. Serialize amount
    calldata.push(core_felt_to_rs(CoreFelt::from(proof.amount)));

    // 4. Serialize hint
    let hint_felts = serialization::serialize_ae_balance(hint_ciphertext, hint_nonce)?;
    for felt in hint_felts {
        calldata.push(core_felt_to_rs(felt));
    }

    // 5. Serialize auxiliarCipher (4 felts: V.x, V.y, R_aux.x, R_aux.y)
    let ac_felts = serialization::serialize_cipher_balance(&proof.auxiliar_cipher)?;
    for felt in ac_felts {
        calldata.push(core_felt_to_rs(felt));
    }

    // 6. Serialize proof (ProofOfWithdraw)
    // Serialize A_x commitment
    let (ax_x, ax_y) = serialization::serialize_projective_point(&proof.a_x)?;
    calldata.push(core_felt_to_rs(ax_x));
    calldata.push(core_felt_to_rs(ax_y));

    // Serialize A_r commitment
    let (ar_x, ar_y) = serialization::serialize_projective_point(&proof.a_r)?;
    calldata.push(core_felt_to_rs(ar_x));
    calldata.push(core_felt_to_rs(ar_y));

    // Serialize A commitment
    let (a_x, a_y) = serialization::serialize_projective_point(&proof.a)?;
    calldata.push(core_felt_to_rs(a_x));
    calldata.push(core_felt_to_rs(a_y));

    // Serialize A_v commitment
    let (av_x, av_y) = serialization::serialize_projective_point(&proof.a_v)?;
    calldata.push(core_felt_to_rs(av_x));
    calldata.push(core_felt_to_rs(av_y));

    // Serialize scalar responses
    calldata.push(core_felt_to_rs(proof.sx));
    calldata.push(core_felt_to_rs(proof.sb));
    calldata.push(core_felt_to_rs(proof.sr));

    // Serialize range proof
    let range_felts = serialization::serialize_range(&proof.range)?;
    for felt in range_felts {
        calldata.push(core_felt_to_rs(felt));
    }

    // 7. Serialize auditPart
    if let Some(ref audit) = proof.audit {
        // CairoOption::Some(Audit)
        // Format: [0, audited_balance (4 felts), hint (6 felts), proof (11 felts)]
        calldata.push(core_felt_to_rs(CoreFelt::ZERO)); // Some variant

        // Serialize audited balance (CipherBalance: 4 felts)
        let balance_felts = serialization::serialize_cipher_balance(&audit.audited_balance)?;
        for felt in balance_felts {
            calldata.push(core_felt_to_rs(felt));
        }

        // Serialize audit hint (AEBalance: 6 felts)
        let audit_hint_felts =
            serialization::serialize_ae_balance(&audit.hint_ciphertext, &audit.hint_nonce)?;
        for felt in audit_hint_felts {
            calldata.push(core_felt_to_rs(felt));
        }

        // Serialize audit proof (11 felts)
        let audit_proof_felts = serialization::serialize_audit_proof(&audit.proof)?;
        for felt in audit_proof_felts {
            calldata.push(core_felt_to_rs(felt));
        }
    } else {
        // CairoOption::None
        calldata.push(core_felt_to_rs(CoreFelt::ONE)); // None variant
    }

    Ok(Call {
        to: core_felt_to_rs(tongo_address),
        selector: get_selector_from_name("withdraw")
            .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
        calldata,
    })
}

/// Build a Call for the Transfer operation.
///
/// Serializes transfer operation with full audit support.
///
/// # Cyclomatic Complexity: 2
#[allow(clippy::too_many_arguments)]
pub fn build_transfer_call(
    tongo_address: CoreFelt,
    from: &starknet_types_core::curve::ProjectivePoint,
    to: &starknet_types_core::curve::ProjectivePoint,
    proof: &TransferProof,
    hint_transfer_ciphertext: &[u8; 64],
    hint_transfer_nonce: &[u8; 24],
    hint_leftover_ciphertext: &[u8; 64],
    hint_leftover_nonce: &[u8; 24],
) -> Result<Call> {
    // Calldata structure (matching Cairo Transfer struct):
    // 1. from: PubKey (2 felts)
    // 2. to: PubKey (2 felts)
    // 3. transferBalance: CipherBalance (4 felts)
    // 4. transferBalanceSelf: CipherBalance (4 felts)
    // 5. hintTransfer: AEBalance (6 felts)
    // 6. hintLeftover: AEBalance (6 felts)
    // 7. auxiliarCipher: CipherBalance (4 felts)
    // 8. auxiliarCipher2: CipherBalance (4 felts)
    // 9. proof: ProofOfTransfer (8 commitments, 5 scalars, 2 range proofs)
    // 10. auditPart: CairoOption<Audit>
    // 11. auditPartTransfer: CairoOption<Audit>

    let mut calldata = Vec::new();

    // 1. Serialize 'from' (sender's public key)
    let (from_x, from_y) = serialization::serialize_projective_point(from)?;
    calldata.push(core_felt_to_rs(from_x));
    calldata.push(core_felt_to_rs(from_y));

    // 2. Serialize 'to' (recipient's public key)
    let (to_x, to_y) = serialization::serialize_projective_point(to)?;
    calldata.push(core_felt_to_rs(to_x));
    calldata.push(core_felt_to_rs(to_y));

    // 3. Serialize transferBalance (CipherBalance: 4 felts - L.x, L.y, R.x, R.y)
    let (tb_l_x, tb_l_y) = serialization::serialize_projective_point(&proof.transfer_balance_l)?;
    let (tb_r_x, tb_r_y) = serialization::serialize_projective_point(&proof.transfer_balance_r)?;
    calldata.push(core_felt_to_rs(tb_l_x));
    calldata.push(core_felt_to_rs(tb_l_y));
    calldata.push(core_felt_to_rs(tb_r_x));
    calldata.push(core_felt_to_rs(tb_r_y));

    // 4. Serialize transferBalanceSelf (encrypted for sender)
    let (tbs_l_x, tbs_l_y) =
        serialization::serialize_projective_point(&proof.transfer_balance_self_l)?;
    let (tbs_r_x, tbs_r_y) =
        serialization::serialize_projective_point(&proof.transfer_balance_self_r)?;
    calldata.push(core_felt_to_rs(tbs_l_x));
    calldata.push(core_felt_to_rs(tbs_l_y));
    calldata.push(core_felt_to_rs(tbs_r_x));
    calldata.push(core_felt_to_rs(tbs_r_y));

    // 5. Serialize hintTransfer
    let hint_transfer =
        serialization::serialize_ae_balance(hint_transfer_ciphertext, hint_transfer_nonce)?;
    for felt in hint_transfer {
        calldata.push(core_felt_to_rs(felt));
    }

    // 6. Serialize hintLeftover
    let hint_leftover =
        serialization::serialize_ae_balance(hint_leftover_ciphertext, hint_leftover_nonce)?;
    for felt in hint_leftover {
        calldata.push(core_felt_to_rs(felt));
    }

    // 7. Serialize auxiliarCipher (4 felts: V.x, V.y, R_aux.x, R_aux.y)
    let ac_felts = serialization::serialize_cipher_balance(&proof.auxiliar_cipher)?;
    for felt in ac_felts {
        calldata.push(core_felt_to_rs(felt));
    }

    // 8. Serialize auxiliarCipher2 (4 felts: V2.x, V2.y, R_aux2.x, R_aux2.y)
    let ac2_felts = serialization::serialize_cipher_balance(&proof.auxiliar_cipher2)?;
    for felt in ac2_felts {
        calldata.push(core_felt_to_rs(felt));
    }

    // 9. Serialize proof (ProofOfTransfer)
    // This includes 8 commitments, 5 scalars, and 2 range proofs
    let proof_felts = serialization::serialize_proof_of_transfer(&proof.proof)?;
    for felt in proof_felts {
        calldata.push(core_felt_to_rs(felt));
    }

    // 10. Serialize auditPart (sender's balance after transfer)
    if let Some(ref audit) = proof.audit_balance {
        // CairoOption::Some = 0
        calldata.push(core_felt_to_rs(CoreFelt::ZERO));

        // Serialize audited balance (CipherBalance: 4 felts)
        let balance_felts = serialization::serialize_cipher_balance(&audit.audited_balance)?;
        for felt in balance_felts {
            calldata.push(core_felt_to_rs(felt));
        }

        // Serialize audit hint (AEBalance: 6 felts)
        let audit_hint_felts =
            serialization::serialize_ae_balance(&audit.hint_ciphertext, &audit.hint_nonce)?;
        for felt in audit_hint_felts {
            calldata.push(core_felt_to_rs(felt));
        }

        // Serialize audit proof (11 felts)
        let audit_proof_felts = serialization::serialize_audit_proof(&audit.proof)?;
        for felt in audit_proof_felts {
            calldata.push(core_felt_to_rs(felt));
        }
    } else {
        // CairoOption::None = 1
        calldata.push(core_felt_to_rs(CoreFelt::ONE));
    }

    // 11. Serialize auditPartTransfer (transfer cipher audit)
    if let Some(ref audit) = proof.audit_transfer {
        // CairoOption::Some = 0
        calldata.push(core_felt_to_rs(CoreFelt::ZERO));

        // Serialize audited balance (CipherBalance: 4 felts)
        let balance_felts = serialization::serialize_cipher_balance(&audit.audited_balance)?;
        for felt in balance_felts {
            calldata.push(core_felt_to_rs(felt));
        }

        // Serialize audit hint (AEBalance: 6 felts)
        let audit_hint_felts =
            serialization::serialize_ae_balance(&audit.hint_ciphertext, &audit.hint_nonce)?;
        for felt in audit_hint_felts {
            calldata.push(core_felt_to_rs(felt));
        }

        // Serialize audit proof (11 felts)
        let audit_proof_felts = serialization::serialize_audit_proof(&audit.proof)?;
        for felt in audit_proof_felts {
            calldata.push(core_felt_to_rs(felt));
        }
    } else {
        // CairoOption::None = 1
        calldata.push(core_felt_to_rs(CoreFelt::ONE));
    }

    Ok(Call {
        to: core_felt_to_rs(tongo_address),
        selector: get_selector_from_name("transfer")
            .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
        calldata,
    })
}

/// Build a Call for the Ragequit operation.
///
/// Ragequit withdraws the ENTIRE balance, leaving the account with 0.
/// Reference: typescript-reference/tongo-sdk/src/operations/ragequit.ts:53-64
///
/// # Cyclomatic Complexity: 2
pub fn build_ragequit_call(
    tongo_address: CoreFelt,
    proof: &RagequitProof,
    hint_ciphertext: &[u8; 64],
    hint_nonce: &[u8; 24],
) -> Result<Call> {
    // Calldata structure (MUST match Cairo struct order):
    // 1. from.x, from.y (2 felts)
    // 2. to (1 felt)
    // 3. amount (1 felt)
    // 4. hint (6 felts)
    // 5. proof.Ax.x, proof.Ax.y, proof.AR.x, proof.AR.y, proof.sx (5 felts)
    // 6. auditPart (Option: 1 felt + 21 felts if Some)

    let mut calldata = Vec::new();

    // 1. Serialize 'from' public key (y)
    let (from_x, from_y) = serialization::serialize_projective_point(&proof.y)?;
    calldata.push(core_felt_to_rs(from_x));
    calldata.push(core_felt_to_rs(from_y));

    // 2. Serialize 'to' recipient address
    calldata.push(core_felt_to_rs(proof.recipient));

    // 3. Serialize amount
    calldata.push(core_felt_to_rs(CoreFelt::from(proof.amount)));

    // 4. Serialize hint (AEBalance: 6 felts)
    let hint_felts = serialization::serialize_ae_balance(hint_ciphertext, hint_nonce)?;
    for felt in hint_felts {
        calldata.push(core_felt_to_rs(felt));
    }

    // 5. Serialize proof (Ax, AR, sx)
    // Ax (2 felts)
    let (ax_x, ax_y) = serialization::serialize_projective_point(&proof.a_x)?;
    calldata.push(core_felt_to_rs(ax_x));
    calldata.push(core_felt_to_rs(ax_y));

    // AR (2 felts)
    let (ar_x, ar_y) = serialization::serialize_projective_point(&proof.a_r)?;
    calldata.push(core_felt_to_rs(ar_x));
    calldata.push(core_felt_to_rs(ar_y));

    // sx (1 felt)
    calldata.push(core_felt_to_rs(proof.sx));

    // 6. Serialize auditPart (Optional)
    if let Some(ref audit) = proof.audit {
        // CairoOption::Some = 0
        calldata.push(core_felt_to_rs(CoreFelt::ZERO));

        // Serialize audited balance (CipherBalance: 4 felts)
        let balance_felts = serialization::serialize_cipher_balance(&audit.audited_balance)?;
        for felt in balance_felts {
            calldata.push(core_felt_to_rs(felt));
        }

        // Serialize audit hint (AEBalance: 6 felts)
        let audit_hint_felts =
            serialization::serialize_ae_balance(&audit.hint_ciphertext, &audit.hint_nonce)?;
        for felt in audit_hint_felts {
            calldata.push(core_felt_to_rs(felt));
        }

        // Serialize audit proof (11 felts)
        let audit_proof_felts = serialization::serialize_audit_proof(&audit.proof)?;
        for felt in audit_proof_felts {
            calldata.push(core_felt_to_rs(felt));
        }
    } else {
        // CairoOption::None = 1
        calldata.push(core_felt_to_rs(CoreFelt::ONE));
    }

    Ok(Call {
        to: core_felt_to_rs(tongo_address),
        selector: get_selector_from_name("ragequit")
            .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
        calldata,
    })
}

/// Build calls for the Outside Fund operation (no proof required).
///
/// Returns (approve_call, outside_fund_call).
///
/// The approve call approves `amount * rate` ERC-20 tokens.
/// The outside_fund calldata is simply `[to.x, to.y, amount]`.
pub fn build_outside_fund_calls(
    tongo_address: CoreFelt,
    erc20_address: CoreFelt,
    to: &ProjectivePoint,
    amount: u128,
    rate: u128,
) -> Result<(Call, Call)> {
    // 1. Build ERC20 approve call
    let approve_amount = amount * rate;
    let approve_call = build_erc20_approve(erc20_address, tongo_address, approve_amount)?;

    // 2. Build outside_fund call: [to.x, to.y, amount]
    let (to_x, to_y) = serialization::serialize_projective_point(to)?;

    let calldata = vec![
        core_felt_to_rs(to_x),
        core_felt_to_rs(to_y),
        core_felt_to_rs(CoreFelt::from(amount)),
    ];

    let outside_fund_call = Call {
        to: core_felt_to_rs(tongo_address),
        selector: get_selector_from_name("outside_fund")
            .map_err(|e| krusty_kms_common::KmsError::CryptoError(e.to_string()))?,
        calldata,
    };

    Ok((approve_call, outside_fund_call))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_erc20_approve() {
        let erc20 = CoreFelt::from(0x123u64);
        let spender = CoreFelt::from(0x456u64);
        let amount = 1000u128;

        let call = build_erc20_approve(erc20, spender, amount).unwrap();

        // Should have selector for "approve" and 3 felts (spender, low, high)
        assert_eq!(call.calldata.len(), 3);
    }

    // Note: Full operation tests would require creating complete proof structures
    // which is complex. Integration tests will verify the full flow.

    #[test]
    fn test_build_outside_fund_calls() {
        use starknet_types_core::curve::ProjectivePoint;
        use starknet_types_core::felt::Felt;

        let tongo = CoreFelt::from(0x111u64);
        let erc20 = CoreFelt::from(0x222u64);
        let amount = 500u128;
        let rate = 10u128;

        // Use a known point (generator)
        let g_x =
            Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
                .unwrap();
        let g_y =
            Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
                .unwrap();
        let to = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        let (approve_call, fund_call) =
            build_outside_fund_calls(tongo, erc20, &to, amount, rate).unwrap();

        // Approve call should have 3 felts: spender, low, high
        assert_eq!(approve_call.calldata.len(), 3);

        // Outside fund call should have 3 felts: to.x, to.y, amount
        assert_eq!(fund_call.calldata.len(), 3);
    }
}
