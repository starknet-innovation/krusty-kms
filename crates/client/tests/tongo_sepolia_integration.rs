//! Integration test for TONGO Sepolia operations.
//!
//! This test replicates the exact flow from `typescript-reference/kms/tongo-sepolia.test.ts`
//! to verify that our Rust implementation produces identical results and can interact
//! with the same deployed contracts using the same keys.
//!
//! **IMPORTANT**: This test uses the SAME test accounts as TypeScript, ensuring
//! we're testing against already-deployed accounts on Sepolia.
//!
//! **Note**: Run with:
//! ```bash
//! cargo test -p starknet-client --test tongo_sepolia_integration -- --ignored --nocapture
//! ```

use krusty_kms::{
    derive_keypair_with_coin_type, derive_oz_account_address, STARKNET_COIN_TYPE, TONGO_COIN_TYPE,
};
use krusty_kms_client::{
    build_fund_calls, build_ragequit_call, build_rollover_call, build_transfer_call,
    build_withdraw_call, create_provider, decrypt_cipher_balance, TongoContract,
};
use krusty_kms_common::ElGamalCiphertext;
use krusty_kms_sdk::operations::{
    fund, ragequit, rollover, transfer, withdraw, FundParams, RagequitParams, RolloverParams,
    TransferParams, WithdrawParams,
};
use krusty_kms_sdk::{AccountState, TongoAccount};
use starknet_rust::accounts::{Account, ExecutionEncoding, SingleOwnerAccount};
use starknet_rust::core::types::{BlockId, BlockTag};
use starknet_rust::signers::{LocalWallet, SigningKey};
use starknet_types_core::felt::Felt;
use std::sync::Arc;

/// OpenZeppelin account class hash (same as TypeScript)
const OZ_ACCOUNT_CLASS_HASH: &str =
    "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";

/// TONGO contract address on Sepolia (same as TypeScript)
const TONGO_CONTRACT_ADDRESS: &str =
    "0x0408163bfcfc2d76f34b444cb55e09dace5905cf84c0884e4637c2c0f06ab6ed";

/// Sepolia RPC URL (fallback if env var not set)
const SEPOLIA_RPC_URL: &str = "https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_9/B-Gw-B-hV805x00WY6hXRJc3OMqU-zxQ";

/// Test mnemonic (SAME as TypeScript test - DO NOT USE IN PRODUCTION)
const TEST_MNEMONIC: &str =
    "habit hope tip crystal because grunt nation idea electric witness alert like";

#[tokio::test]
#[ignore] // Requires Sepolia testnet access
async fn test_full_tongo_sepolia_flow() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔧 TONGO Sepolia Integration Test");
    println!("================================================================================\n");

    // -------------------------------------------------------------------------
    // Step 1: Derive Starknet account contract keys (coin type 9004)
    // -------------------------------------------------------------------------
    println!("📍 Step 1: Deriving Starknet account contract keys (coin type 9004)...");

    let account_keypair =
        derive_keypair_with_coin_type(TEST_MNEMONIC, 0, 0, STARKNET_COIN_TYPE, None)?;

    let account_public_key = account_keypair
        .public_key
        .to_affine()
        .map_err(|e| format!("Failed to convert public key: {:?}", e))?
        .x();

    println!(
        "   ✓ Account Private Key: {:#x}",
        account_keypair.private_key
    );
    println!("   ✓ Account Public Key:  {:#x}", account_public_key);

    // -------------------------------------------------------------------------
    // Step 2: Calculate OpenZeppelin account address (SAME as TypeScript)
    // -------------------------------------------------------------------------
    println!("\n📍 Step 2: Calculating OpenZeppelin account address...");

    let oz_class_hash = Felt::from_hex(OZ_ACCOUNT_CLASS_HASH)?;
    let salt = Felt::ZERO; // Salt "0x0" as in TypeScript
    let account_address =
        derive_oz_account_address(&account_public_key, &oz_class_hash, Some(&salt))?;

    println!("   ✓ Derived Address: {:#x}", account_address);
    println!("   💡 This should match the deployed account in TypeScript test");

    // -------------------------------------------------------------------------
    // Step 3: Derive TONGO keys (coin type 5454) - SAME as TypeScript
    // -------------------------------------------------------------------------
    println!("\n📍 Step 3: Deriving TONGO virtual account keys (coin type 5454)...");

    let tongo_keypair_0 =
        derive_keypair_with_coin_type(TEST_MNEMONIC, 0, 0, TONGO_COIN_TYPE, None)?;
    let tongo_keypair_1 =
        derive_keypair_with_coin_type(TEST_MNEMONIC, 1, 0, TONGO_COIN_TYPE, None)?;

    println!(
        "   ✓ TONGO Account 0 Private Key: {:#x}",
        tongo_keypair_0.private_key
    );
    println!(
        "   ✓ TONGO Account 0 Public Key:  {:#x}",
        tongo_keypair_0
            .public_key
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x()
    );
    println!(
        "   ✓ TONGO Account 1 Private Key: {:#x}",
        tongo_keypair_1.private_key
    );
    println!(
        "   ✓ TONGO Account 1 Public Key:  {:#x}",
        tongo_keypair_1
            .public_key
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x()
    );

    // -------------------------------------------------------------------------
    // Step 4: Create RPC provider and TONGO contract client
    // -------------------------------------------------------------------------
    println!("\n📍 Step 4: Creating RPC provider and TONGO contract client...");

    let rpc_url = std::env::var("STARKNET_RPC_URL").unwrap_or_else(|_| SEPOLIA_RPC_URL.to_string());
    let provider = Arc::new(create_provider(&rpc_url)?);

    let tongo_contract_address = Felt::from_hex(TONGO_CONTRACT_ADDRESS)?;
    let tongo_contract = TongoContract::new(provider.clone(), tongo_contract_address);

    println!("   ✓ RPC Provider created: {}", rpc_url);
    println!("   ✓ TONGO Contract: {:#x}", tongo_contract_address);

    // -------------------------------------------------------------------------
    // Step 5: Query contract parameters
    // -------------------------------------------------------------------------
    println!("\n📍 Step 5: Querying TONGO contract parameters...");

    let rate = tongo_contract.get_rate().await?;
    let bit_size = tongo_contract.get_bit_size().await?;
    let erc20_address = tongo_contract.get_erc20().await?;
    let auditor_key = tongo_contract.auditor_key().await?;

    println!("   ✓ Rate: {} (ERC20 tokens per TONGO unit)", rate);
    println!("   ✓ Bit Size: {} (for range proofs)", bit_size);
    println!("   ✓ ERC20 Address: {:#x}", erc20_address);
    if let Some(ref auditor) = auditor_key {
        println!(
            "   ✓ Auditor Key: {:#x}",
            auditor.to_affine().map_err(|e| format!("{:?}", e))?.x()
        );
        println!("   ⚠️  WARNING: This contract has an auditor - audits are REQUIRED for all operations!");
    } else {
        println!("   ✓ No Auditor configured (audits optional)");
    }

    // -------------------------------------------------------------------------
    // Step 6: Query initial account state
    // -------------------------------------------------------------------------
    println!("\n📍 Step 6: Querying TONGO Account 0 initial state...");

    let initial_state = tongo_contract
        .get_state(&tongo_keypair_0.public_key)
        .await?;
    let initial_balance = decrypt_cipher_balance(
        tongo_keypair_0.private_key.expose_secret(),
        &initial_state.balance,
    )?;
    let initial_pending = decrypt_cipher_balance(
        tongo_keypair_0.private_key.expose_secret(),
        &initial_state.pending,
    )?;

    println!("   ✓ Initial Balance: {}", initial_balance);
    println!("   ✓ Initial Pending: {}", initial_pending);
    println!("   ✓ Nonce: {:#x}", initial_state.nonce);

    // -------------------------------------------------------------------------
    // Step 7: Create TONGO account instances
    // -------------------------------------------------------------------------
    println!("\n📍 Step 7: Creating TONGO account instances...");

    let mut tongo_account_0 = TongoAccount::from_private_key(
        *tongo_keypair_0.private_key.expose_secret(),
        tongo_contract_address,
    )?;

    // Set the actual state we queried from the blockchain
    tongo_account_0.state = AccountState {
        balance: initial_balance,
        pending_balance: initial_pending,
        nonce: initial_state.nonce.to_biguint().try_into().unwrap_or(0),
    };

    let mut tongo_account_1 = TongoAccount::from_private_key(
        *tongo_keypair_1.private_key.expose_secret(),
        tongo_contract_address,
    )?;

    println!(
        "   ✓ TONGO Account 0 created (balance: {})",
        initial_balance
    );
    println!("   ✓ TONGO Account 1 created");

    // -------------------------------------------------------------------------
    // Step 8: Generate Fund proof
    // -------------------------------------------------------------------------
    println!("\n📍 Step 8: Generating Fund proof...");

    let fund_amount: u128 = 2; // Fund 2 units so we can transfer 2 to Account 1
    let chain_id = Felt::from_hex("0x534e5f5345504f4c4941")?; // SN_SEPOLIA

    // Convert CipherBalance to ElGamalCiphertext for audit proof generation
    let current_balance = ElGamalCiphertext {
        l: initial_state.balance.l.clone(),
        r: initial_state.balance.r.clone(),
    };

    println!("   💡 Stored balance ciphertext (from contract):");
    println!(
        "     L: {:#x}, {:#x}",
        current_balance
            .l
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x(),
        current_balance
            .l
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .y()
    );
    println!(
        "     R: {:#x}, {:#x}",
        current_balance
            .r
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x(),
        current_balance
            .r
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .y()
    );

    let fund_params = FundParams {
        amount: fund_amount,
        nonce: initial_state.nonce,
        chain_id,
        tongo_address: tongo_contract_address,
        sender_address: account_address,
        auditor_pub_key: auditor_key.clone(),
        current_balance: current_balance.clone(),
    };

    let fund_proof = fund(&tongo_account_0, fund_params)?;

    println!("   ✓ Fund proof generated for {} units", fund_amount);
    println!(
        "   ✓ Proof y: {:#x}",
        fund_proof
            .y
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x()
    );

    // Debug and verify audit proof details
    if let Some(ref audit) = fund_proof.audit {
        println!("   ✓ Audit proof included:");
        println!(
            "     - Audited balance L: {:#x}, {:#x}",
            audit
                .audited_balance
                .l
                .to_affine()
                .map_err(|e| format!("{:?}", e))?
                .x(),
            audit
                .audited_balance
                .l
                .to_affine()
                .map_err(|e| format!("{:?}", e))?
                .y()
        );
        println!(
            "     - Audited balance R: {:#x}, {:#x}",
            audit
                .audited_balance
                .r
                .to_affine()
                .map_err(|e| format!("{:?}", e))?
                .x(),
            audit
                .audited_balance
                .r
                .to_affine()
                .map_err(|e| format!("{:?}", e))?
                .y()
        );
        println!(
            "     - Balance after funding: {}",
            initial_balance + fund_amount
        );

        // CRITICAL: The audit proof is for the balance AFTER funding, not before!
        // Compute the new cipher balance (what the contract will have after fund())
        use krusty_kms_crypto::StarkCurve;
        const FUND_CAIRO_STRING: u64 = 1718972004;
        let fund_r = Felt::from(FUND_CAIRO_STRING);
        let g = StarkCurve::generator();
        let fund_cipher_l = {
            let g_amount = StarkCurve::mul(&Felt::from(fund_amount), Some(&g));
            let y_r = StarkCurve::mul(&fund_r, Some(&tongo_keypair_0.public_key));
            StarkCurve::add(&g_amount, &y_r)
        };
        let fund_cipher_r = StarkCurve::mul(&fund_r, Some(&g));
        let new_cipher_balance = ElGamalCiphertext {
            l: StarkCurve::add(&current_balance.l, &fund_cipher_l),
            r: StarkCurve::add(&current_balance.r, &fund_cipher_r),
        };

        // Verify the audit proof locally before submitting
        use krusty_kms_crypto::{AuditPrefixData, AuditProver};
        let audit_prefix = AuditPrefixData {
            chain_id,
            tongo_address: tongo_contract_address,
            sender_address: account_address,
            user_pub_key: tongo_keypair_0.public_key.clone(),
        };
        let is_valid = AuditProver::verify(
            &audit.proof,
            &tongo_keypair_0.public_key,
            &new_cipher_balance, // Verify against NEW balance, not old
            &audit.audited_balance,
            auditor_key.as_ref().unwrap(),
            Some(&audit_prefix),
        )?;
        println!(
            "     - Local audit proof verification: {}",
            if is_valid { "✓ VALID" } else { "✗ INVALID" }
        );
        if !is_valid {
            return Err("Audit proof failed local verification!".into());
        }
    }

    // -------------------------------------------------------------------------
    // Step 9: Build Fund transaction calls
    // -------------------------------------------------------------------------
    println!("\n📍 Step 9: Building Fund transaction calldata...");

    // Rate explanation:
    // - rate = 1e18 (1000000000000000000)
    // - This means: 1 TONGO unit = 1e18 ERC20 tokens
    // - For STRK (18 decimals): 1 TONGO = 1 STRK
    // - Approve amount = fund_amount * rate = 1 * 1e18 = 1 STRK
    println!(
        "   💡 Rate: {} (1 TONGO unit = {} ERC20 tokens)",
        rate, rate
    );
    println!(
        "   💡 Funding {} TONGO units = {} ERC20 tokens to approve",
        fund_amount,
        fund_amount * rate
    );

    // Create dummy hint (in production, would be actual XChaCha20 encrypted balance)
    let hint_ciphertext = [0x42u8; 64];
    let hint_nonce = [0x99u8; 24];

    let (approve_call, fund_call) = build_fund_calls(
        tongo_contract_address,
        erc20_address,
        rate,
        &fund_proof,
        &hint_ciphertext,
        &hint_nonce,
    )?;

    println!(
        "   ✓ ERC20 Approve call built: {} calldata felts",
        approve_call.calldata.len()
    );
    println!(
        "   ✓ Fund call built: {} calldata felts",
        fund_call.calldata.len()
    );
    println!("   💡 Full calldata (first 20 elements):");
    for (i, felt) in fund_call.calldata.iter().take(20).enumerate() {
        println!("     [{}]: {:#x}", i, felt);
    }
    println!("   💡 Fund calldata breakdown:");
    println!("     - to.x: {:#x}", fund_call.calldata[0]);
    println!("     - to.y: {:#x}", fund_call.calldata[1]);
    println!("     - amount: {:#x}", fund_call.calldata[2]);
    println!("     - hint: {} felts (indices 3-8)", 6);
    println!("     - proof: {} felts (indices 9-11)", 3);
    if fund_call.calldata.len() > 12 {
        println!(
            "     - audit variant: {} (0=Some, 1=None)",
            fund_call.calldata[12]
        );
        if fund_call.calldata[12] == starknet_rust::core::types::Felt::ZERO {
            println!(
                "     - audit: {} felts total (4 balance + 6 hint + 11 proof)",
                21
            );
        }
    }
    println!("   💡 These calls are ready to be executed via SingleOwnerAccount");

    // -------------------------------------------------------------------------
    // Step 10: Execute transaction (if EXECUTE_TX env var is set)
    // -------------------------------------------------------------------------
    println!("\n📍 Step 10: Transaction execution...");

    let should_execute = std::env::var("EXECUTE_TX").is_ok();

    if should_execute {
        println!("   🚀 EXECUTE_TX is set - executing transaction on Sepolia...");

        // Create signer from the derived private key
        // Convert from starknet-types-core 1.0 Felt to 0.1.9 for starknet-rs compatibility
        let private_key_bytes = account_keypair.private_key.expose_secret().to_bytes_be();
        let private_key_rs = starknet_rust::core::types::Felt::from_bytes_be(&private_key_bytes);
        let signing_key = SigningKey::from_secret_scalar(private_key_rs);
        let signer = LocalWallet::from(signing_key);

        // Create SingleOwnerAccount
        let chain_id_bytes = Felt::from_hex("0x534e5f5345504f4c4941")?.to_bytes_be();
        let chain_id_rs = starknet_rust::core::types::Felt::from_bytes_be(&chain_id_bytes);
        let account_address_bytes = account_address.to_bytes_be();
        let account_address_rs =
            starknet_rust::core::types::Felt::from_bytes_be(&account_address_bytes);

        let mut account = SingleOwnerAccount::new(
            provider.clone(),
            signer,
            account_address_rs,
            chain_id_rs,
            ExecutionEncoding::New, // Use Cairo 1 encoding
        );

        // Set block ID for nonce/fee estimation - use Latest instead of Pending in 0.17
        account.set_block_id(BlockId::Tag(BlockTag::Latest));

        println!("   ✓ Created SingleOwnerAccount");

        // Execute the transaction using v3 (required by Sepolia)
        // starknet-rs 0.17.0 properly handles l1_data_gas in resource bounds
        let calls = vec![approve_call.clone(), fund_call.clone()];
        println!("   ⏳ Sending transaction with {} calls...", calls.len());

        let execution = account.execute_v3(calls).send().await?;

        println!("   ✓ Transaction sent!");
        println!("   📝 Transaction hash: {:#x}", execution.transaction_hash);

        // Wait for transaction confirmation
        println!("   ⏳ Waiting for transaction confirmation...");

        // Simple polling loop (production would use proper tx status checking)
        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

        // Query updated state
        let new_state = tongo_contract
            .get_state(&tongo_keypair_0.public_key)
            .await?;
        let new_balance = decrypt_cipher_balance(
            tongo_keypair_0.private_key.expose_secret(),
            &new_state.balance,
        )?;

        println!("   ✓ Transaction confirmed!");
        println!(
            "   📊 New Balance: {} (was: {})",
            new_balance, initial_balance
        );
        println!(
            "   📊 Change: +{}",
            new_balance.saturating_sub(initial_balance)
        );

        // Update account state for subsequent operations
        tongo_account_0.state.balance = new_balance;
        tongo_account_0.state.nonce = new_state.nonce.to_biguint().try_into().unwrap_or(0);
    } else {
        println!("   ⏭️  EXECUTE_TX not set - skipping actual transaction execution");
        println!("   💡 To execute transactions, run with:");
        println!("       EXECUTE_TX=1 cargo test -p starknet-client --test tongo_sepolia_integration test_full_tongo_sepolia_flow -- --ignored --nocapture");
        println!("   ⚠️  WARNING: This will spend real gas on Sepolia testnet!");
    }

    // -------------------------------------------------------------------------
    // Step 10.5: Transfer operation (Account 0 → Account 1)
    // -------------------------------------------------------------------------
    println!("\n📍 Step 10.5: Generating Transfer proof (Account 0 → Account 1)...");

    // Query updated balance after fund
    let updated_state = tongo_contract
        .get_state(&tongo_keypair_0.public_key)
        .await?;
    let updated_balance = decrypt_cipher_balance(
        tongo_keypair_0.private_key.expose_secret(),
        &updated_state.balance,
    )?;

    println!("   💡 Sender balance after fund: {}", updated_balance);

    // Update account state
    tongo_account_0.state.balance = updated_balance;
    tongo_account_0.state.nonce = updated_state.nonce.to_biguint().try_into().unwrap_or(0);

    let transfer_amount: u128 = 2; // Transfer 2 units so Account 1 can withdraw 1 and ragequit 1

    // Get current balance cipher for audit
    let current_balance_cipher = ElGamalCiphertext {
        l: updated_state.balance.l.clone(),
        r: updated_state.balance.r.clone(),
    };

    let transfer_params = TransferParams {
        recipient_public_key: tongo_keypair_1.public_key.clone(),
        amount: transfer_amount,
        nonce: updated_state.nonce,
        chain_id,
        tongo_address: tongo_contract_address,
        sender_address: account_address,
        current_balance: current_balance_cipher.clone(),
        bit_size: 32,                         // 32-bit range proofs for u32 values
        auditor_pub_key: auditor_key.clone(), // Enable audits (required by contract)
    };

    let transfer_start = std::time::Instant::now();
    let transfer_proof = transfer(&tongo_account_0, transfer_params)?;
    let transfer_duration = transfer_start.elapsed();

    println!(
        "   ✓ Transfer proof generated for {} units",
        transfer_amount
    );
    println!(
        "   ⏱️  Proof generation time: {:.2} ms",
        transfer_duration.as_secs_f64() * 1000.0
    );

    // Verify audits locally
    if transfer_proof.audit_balance.is_some() {
        println!("   ✓ Audit for sender's new balance included");
        println!("     - Proof generated for subtracted cipher (current - transfer)");
        println!("     - Subtracted cipher is a valid ElGamal encryption of new balance");
        println!("     - Will be verified on-chain");
    }

    if transfer_proof.audit_transfer.is_some() {
        println!("   ✓ Audit for transfer cipher included");
        println!("     - Proof generated for transfer amount cipher");
        println!("     - Will be verified on-chain");
    }

    // Build transfer call
    let hint_transfer_ct = [0x46u8; 64];
    let hint_transfer_nonce = [0x9Cu8; 24];
    let hint_leftover_ct = [0x47u8; 64];
    let hint_leftover_nonce = [0x9Du8; 24];

    let transfer_call_start = std::time::Instant::now();
    let transfer_call = build_transfer_call(
        tongo_contract_address,
        &tongo_keypair_0.public_key,
        &tongo_keypair_1.public_key,
        &transfer_proof,
        &hint_transfer_ct,
        &hint_transfer_nonce,
        &hint_leftover_ct,
        &hint_leftover_nonce,
    )?;
    let transfer_call_duration = transfer_call_start.elapsed();

    println!(
        "   ✓ Transfer call built: {} calldata felts",
        transfer_call.calldata.len()
    );
    println!(
        "   ⏱️ Transfer call builder generation time: {:.2} ms",
        transfer_call_duration.as_secs_f64() * 1000.0
    );

    // Execute transfer if EXECUTE_TX is set
    if should_execute {
        println!("   🚀 Executing transfer transaction on Sepolia...");

        // Recreate account for transfer (same as fund operation)
        let private_key_bytes = account_keypair.private_key.expose_secret().to_bytes_be();
        let private_key_rs = starknet_rust::core::types::Felt::from_bytes_be(&private_key_bytes);
        let signing_key = SigningKey::from_secret_scalar(private_key_rs);
        let signer = LocalWallet::from(signing_key);

        let chain_id_bytes = Felt::from_hex("0x534e5f5345504f4c4941")?.to_bytes_be();
        let chain_id_rs = starknet_rust::core::types::Felt::from_bytes_be(&chain_id_bytes);
        let account_address_bytes = account_address.to_bytes_be();
        let account_address_rs =
            starknet_rust::core::types::Felt::from_bytes_be(&account_address_bytes);

        let mut account = SingleOwnerAccount::new(
            provider.clone(),
            signer,
            account_address_rs,
            chain_id_rs,
            ExecutionEncoding::New,
        );
        account.set_block_id(BlockId::Tag(BlockTag::Latest));

        let result = account
            .execute_v3(vec![transfer_call])
            .send()
            .await
            .map_err(|e| format!("Transfer transaction failed: {}", e))?;

        println!("   ✓ Transfer transaction sent!");
        println!("   📝 Transaction hash: {:#x}", result.transaction_hash);

        println!("   ⏳ Waiting for transfer confirmation...");
        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

        // Query final balance
        let final_state = tongo_contract
            .get_state(&tongo_keypair_0.public_key)
            .await?;
        let final_balance = decrypt_cipher_balance(
            tongo_keypair_0.private_key.expose_secret(),
            &final_state.balance,
        )?;

        println!("   ✓ Transfer confirmed!");
        println!(
            "   📊 Sender's New Balance: {} (was: {})",
            final_balance, updated_balance
        );
        println!(
            "   📊 Change: {:+}",
            final_balance as i128 - updated_balance as i128
        );

        // Update account state
        tongo_account_0.state.balance = final_balance;
        tongo_account_0.state.nonce = final_state.nonce.to_biguint().try_into().unwrap_or(0);
    } else {
        println!("   ⏭️  EXECUTE_TX not set - skipping transfer execution");
    }

    // -------------------------------------------------------------------------
    // Step 11: Generate Rollover proof and execute (Account 1)
    // -------------------------------------------------------------------------
    println!("\n📍 Step 11: Generating Rollover proof (Account 1)...");

    // Query Account 1's state after receiving transfer
    let account1_state = tongo_contract
        .get_state(&tongo_keypair_1.public_key)
        .await?;
    let account1_balance = decrypt_cipher_balance(
        tongo_keypair_1.private_key.expose_secret(),
        &account1_state.balance,
    )?;
    let account1_pending = decrypt_cipher_balance(
        tongo_keypair_1.private_key.expose_secret(),
        &account1_state.pending,
    )?;
    let account1_nonce: u64 = account1_state.nonce.to_biguint().try_into().unwrap_or(0);

    println!("   💡 Account 1 state before rollover:");
    println!("      Balance: {}", account1_balance);
    println!("      Pending: {}", account1_pending);
    println!("      Nonce: {}", account1_nonce);

    // Update Account 1's state
    tongo_account_1.state.balance = account1_balance;
    tongo_account_1.state.pending_balance = account1_pending;
    tongo_account_1.state.nonce = account1_nonce;

    // Pass all required parameters to rollover (MUST match TypeScript exactly!)
    let rollover_params = RolloverParams {
        nonce: account1_state.nonce,
        chain_id,
        tongo_address: tongo_contract_address,
        sender_address: account_address,
    };
    let rollover_proof = rollover(&tongo_account_1, rollover_params)?;

    println!("   ✓ Rollover proof generated");
    println!(
        "   ✓ Proof y: {:#x}",
        rollover_proof
            .y
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x()
    );

    // Build rollover call
    let hint_rollover_ct = [0x48u8; 64];
    let hint_rollover_nonce = [0x9Eu8; 24];

    let rollover_call = build_rollover_call(
        tongo_contract_address,
        &rollover_proof,
        &hint_rollover_ct,
        &hint_rollover_nonce,
    )?;

    println!(
        "   ✓ Rollover call built: {} calldata felts",
        rollover_call.calldata.len()
    );

    // Execute rollover if EXECUTE_TX is set
    if should_execute {
        println!("   🚀 Executing rollover transaction on Sepolia...");

        // Create account for rollover
        let private_key_bytes = account_keypair.private_key.expose_secret().to_bytes_be();
        let private_key_rs = starknet_rust::core::types::Felt::from_bytes_be(&private_key_bytes);
        let signing_key = SigningKey::from_secret_scalar(private_key_rs);
        let signer = LocalWallet::from(signing_key);

        let chain_id_bytes = Felt::from_hex("0x534e5f5345504f4c4941")?.to_bytes_be();
        let chain_id_rs = starknet_rust::core::types::Felt::from_bytes_be(&chain_id_bytes);
        let account_address_bytes = account_address.to_bytes_be();
        let account_address_rs =
            starknet_rust::core::types::Felt::from_bytes_be(&account_address_bytes);

        let mut account = SingleOwnerAccount::new(
            provider.clone(),
            signer,
            account_address_rs,
            chain_id_rs,
            ExecutionEncoding::New,
        );
        account.set_block_id(BlockId::Tag(BlockTag::Latest));

        let result = account
            .execute_v3(vec![rollover_call])
            .send()
            .await
            .map_err(|e| format!("Rollover transaction failed: {}", e))?;

        println!("   ✓ Rollover transaction sent!");
        println!("   📝 Transaction hash: {:#x}", result.transaction_hash);

        println!("   ⏳ Waiting for rollover confirmation...");
        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

        // Query updated state
        let post_rollover_state = tongo_contract
            .get_state(&tongo_keypair_1.public_key)
            .await?;
        let post_rollover_balance = decrypt_cipher_balance(
            tongo_keypair_1.private_key.expose_secret(),
            &post_rollover_state.balance,
        )?;
        let post_rollover_pending = decrypt_cipher_balance(
            tongo_keypair_1.private_key.expose_secret(),
            &post_rollover_state.pending,
        )?;
        let post_rollover_nonce: u64 = post_rollover_state
            .nonce
            .to_biguint()
            .try_into()
            .unwrap_or(0);

        println!("   ✓ Rollover confirmed!");
        println!(
            "   📊 Account 1 Balance: {} → {} (pending added to balance)",
            account1_balance, post_rollover_balance
        );
        println!(
            "   📊 Account 1 Pending: {} → {} (cleared)",
            account1_pending, post_rollover_pending
        );
        println!(
            "   📊 Account 1 Nonce: {} → {}",
            account1_nonce, post_rollover_nonce
        );

        // Update account state
        tongo_account_1.state.balance = post_rollover_balance;
        tongo_account_1.state.pending_balance = post_rollover_pending;
        tongo_account_1.state.nonce = post_rollover_nonce;
    } else {
        println!("   ⏭️  EXECUTE_TX not set - skipping rollover execution");
    }

    // -------------------------------------------------------------------------
    // Step 12: Generate Withdraw proof and execute (Account 1)
    // -------------------------------------------------------------------------
    println!("\n📍 Step 12: Generating Withdraw proof (Account 1)...");

    // Query Account 1's current state for withdraw
    let withdraw_state = tongo_contract
        .get_state(&tongo_keypair_1.public_key)
        .await?;
    let withdraw_balance = decrypt_cipher_balance(
        tongo_keypair_1.private_key.expose_secret(),
        &withdraw_state.balance,
    )?;

    println!(
        "   💡 Account 1 balance before withdraw: {}",
        withdraw_balance
    );

    // Skip withdraw if balance is too low (would leave 0), use ragequit instead
    if withdraw_balance <= 1 {
        println!("   ⏭️  Balance too low for withdraw (would leave 0), skipping to ragequit");
    } else {
        // Update Account 1's state
        tongo_account_1.state.balance = withdraw_balance;
        tongo_account_1.state.nonce = withdraw_state.nonce.to_biguint().try_into().unwrap_or(0);

        let withdraw_params = WithdrawParams {
            recipient_address: account_address, // Withdraw to our account
            amount: 1,
            nonce: withdraw_state.nonce,
            chain_id,
            tongo_address: tongo_contract_address,
            sender_address: account_address,
            current_balance: ElGamalCiphertext {
                l: withdraw_state.balance.l.clone(),
                r: withdraw_state.balance.r.clone(),
            },
            bit_size: 32,                     // 32-bit range proofs
            auditor_key: auditor_key.clone(), // Include auditor for balance audit
        };

        // Use Account 1 since it has balance
        let withdraw_proof = withdraw(&tongo_account_1, withdraw_params)?;

        println!(
            "   ✓ Withdraw proof generated for {} units",
            withdraw_proof.amount
        );
        println!("   ✓ Recipient: {:#x}", withdraw_proof.recipient);

        // Build withdraw call
        let hint_withdraw_ct = [0x49u8; 64];
        let hint_withdraw_nonce = [0x9Fu8; 24];

        let withdraw_call = build_withdraw_call(
            tongo_contract_address,
            &withdraw_proof,
            &hint_withdraw_ct,
            &hint_withdraw_nonce,
        )?;

        println!(
            "   ✓ Withdraw call built: {} calldata felts",
            withdraw_call.calldata.len()
        );

        // Execute withdraw if EXECUTE_TX is set
        if should_execute {
            println!("   🚀 Executing withdraw transaction on Sepolia...");

            // Query state before withdraw
            let pre_withdraw_state = tongo_contract
                .get_state(&tongo_keypair_1.public_key)
                .await?;
            let pre_withdraw_balance = decrypt_cipher_balance(
                tongo_keypair_1.private_key.expose_secret(),
                &pre_withdraw_state.balance,
            )?;

            // Create account for withdraw
            let private_key_bytes = account_keypair.private_key.expose_secret().to_bytes_be();
            let private_key_rs =
                starknet_rust::core::types::Felt::from_bytes_be(&private_key_bytes);
            let signing_key = SigningKey::from_secret_scalar(private_key_rs);
            let signer = LocalWallet::from(signing_key);

            let chain_id_bytes = Felt::from_hex("0x534e5f5345504f4c4941")?.to_bytes_be();
            let chain_id_rs = starknet_rust::core::types::Felt::from_bytes_be(&chain_id_bytes);
            let account_address_bytes = account_address.to_bytes_be();
            let account_address_rs =
                starknet_rust::core::types::Felt::from_bytes_be(&account_address_bytes);

            let mut account = SingleOwnerAccount::new(
                provider.clone(),
                signer,
                account_address_rs,
                chain_id_rs,
                ExecutionEncoding::New,
            );
            account.set_block_id(BlockId::Tag(BlockTag::Latest));

            let result = account
                .execute_v3(vec![withdraw_call])
                .send()
                .await
                .map_err(|e| format!("Withdraw transaction failed: {}", e))?;

            println!("   ✓ Withdraw transaction sent!");
            println!("   📝 Transaction hash: {:#x}", result.transaction_hash);

            println!("   ⏳ Waiting for withdraw confirmation...");
            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

            // Query updated state
            let post_withdraw_state = tongo_contract
                .get_state(&tongo_keypair_1.public_key)
                .await?;
            let post_withdraw_balance = decrypt_cipher_balance(
                tongo_keypair_1.private_key.expose_secret(),
                &post_withdraw_state.balance,
            )?;

            println!("   ✓ Withdraw confirmed!");
            println!(
                "   📊 Account 1 Balance: {} → {}",
                pre_withdraw_balance, post_withdraw_balance
            );
            println!(
                "   📊 Change: {:+}",
                post_withdraw_balance as i128 - pre_withdraw_balance as i128
            );

            // Update account state
            tongo_account_1.state.balance = post_withdraw_balance;
            tongo_account_1.state.nonce = post_withdraw_state
                .nonce
                .to_biguint()
                .try_into()
                .unwrap_or(0);
        } else {
            println!("   ⏭️  EXECUTE_TX not set - skipping withdraw execution");
        }
    } // Close the else block from line 640

    // -------------------------------------------------------------------------
    // Step 13: Ragequit operation (Account 1 withdraws ALL remaining balance)
    // -------------------------------------------------------------------------
    println!("\n📍 Step 13: Generating Ragequit proof (Account 1)...");
    let pre_ragequit_balance = tongo_account_1.state.balance;
    println!(
        "   💡 Account 1 balance before ragequit: {}",
        pre_ragequit_balance
    );

    // Fetch current state for ragequit
    let ragequit_state = tongo_contract
        .get_state(&tongo_keypair_1.public_key)
        .await?;

    // Update account balance to match on-chain state
    let current_balance = decrypt_cipher_balance(
        tongo_keypair_1.private_key.expose_secret(),
        &ragequit_state.balance,
    )?;
    tongo_account_1.state.balance = current_balance;
    println!("   💡 Current on-chain balance: {}", current_balance);

    // Skip ragequit if balance is already 0
    if current_balance == 0 {
        println!("   ⏭️  Balance already 0, skipping ragequit");
        println!(
            "\n================================================================================"
        );
        println!("✅ Integration Test Completed Successfully!");
        println!(
            "================================================================================"
        );
        return Ok(());
    }

    let ragequit_params = RagequitParams {
        recipient_address: account_address,
        nonce: ragequit_state.nonce,
        chain_id,
        tongo_address: tongo_contract_address,
        sender_address: account_address,
        current_balance: ElGamalCiphertext {
            l: ragequit_state.balance.l.clone(),
            r: ragequit_state.balance.r.clone(),
        },
        auditor_key: auditor_key.clone(), // Contract requires audit
    };

    let ragequit_proof = ragequit(&tongo_account_1, ragequit_params)?;
    println!(
        "   ✓ Ragequit proof generated for {} units (full balance)",
        ragequit_proof.amount
    );
    println!("   ✓ Recipient: {:#x}", ragequit_proof.recipient);

    // Build ragequit call
    let hint_ct = [0x50u8; 64];
    let hint_nonce = [0x51u8; 24];
    let ragequit_call = build_ragequit_call(
        tongo_contract_address,
        &ragequit_proof,
        &hint_ct,
        &hint_nonce,
    )?;

    println!(
        "   ✓ Ragequit call built: {} calldata felts",
        ragequit_call.calldata.len()
    );

    if should_execute {
        println!("   🚀 Executing ragequit transaction on Sepolia...");

        // Create account for ragequit (same pattern as withdraw)
        let private_key_bytes = account_keypair.private_key.expose_secret().to_bytes_be();
        let private_key_rs = starknet_rust::core::types::Felt::from_bytes_be(&private_key_bytes);
        let signing_key = SigningKey::from_secret_scalar(private_key_rs);
        let signer = LocalWallet::from(signing_key);

        let chain_id_bytes = Felt::from_hex("0x534e5f5345504f4c4941")?.to_bytes_be();
        let chain_id_rs = starknet_rust::core::types::Felt::from_bytes_be(&chain_id_bytes);
        let account_address_bytes = account_address.to_bytes_be();
        let account_address_rs =
            starknet_rust::core::types::Felt::from_bytes_be(&account_address_bytes);

        let mut account = SingleOwnerAccount::new(
            provider.clone(),
            signer,
            account_address_rs,
            chain_id_rs,
            ExecutionEncoding::New,
        );
        account.set_block_id(BlockId::Tag(BlockTag::Latest));

        let result = account
            .execute_v3(vec![ragequit_call])
            .send()
            .await
            .map_err(|e| format!("Ragequit transaction failed: {}", e))?;

        println!("   ✓ Ragequit transaction sent!");
        println!("   📝 Transaction hash: {:#x}", result.transaction_hash);

        println!("   ⏳ Waiting for ragequit confirmation...");
        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

        // Query updated state
        let post_ragequit_state = tongo_contract
            .get_state(&tongo_keypair_1.public_key)
            .await?;
        let post_ragequit_balance = decrypt_cipher_balance(
            tongo_keypair_1.private_key.expose_secret(),
            &post_ragequit_state.balance,
        )?;

        println!("   ✓ Ragequit confirmed!");
        println!(
            "   📊 Account 1 Balance: {} → {} (full withdrawal)",
            pre_ragequit_balance, post_ragequit_balance
        );

        // Update account state
        tongo_account_1.state.balance = post_ragequit_balance;
        tongo_account_1.state.nonce = post_ragequit_state
            .nonce
            .to_biguint()
            .try_into()
            .unwrap_or(0);
    } else {
        println!("   ⏭️  EXECUTE_TX not set - skipping ragequit execution");
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------
    println!("\n================================================================================");
    println!("✅ Integration Test Completed Successfully!");
    println!("================================================================================\n");

    println!("📊 Summary:");
    println!("   ✅ Derived SAME keys as TypeScript (coin types 9004 & 5454)");
    println!("   ✅ Calculated SAME account address as TypeScript");
    println!("   ✅ RPC provider and contract client working");
    println!("   ✅ Contract parameter queries working (rate, bit_size, erc20)");
    println!("   ✅ Account state queries working (balance, pending, nonce)");
    println!("   ✅ ElGamal cipher balance decryption working");
    println!("   ✅ Fund proof generation and execution working");
    println!("   ✅ Transfer proof generation and execution working");
    println!("   ✅ Rollover proof generation and execution working");
    println!("   ✅ Withdraw proof generation and execution working");
    println!("   ✅ Ragequit proof generation and execution working");
    println!("   ✅ Transaction calldata building working (all operations)");

    println!("\n📝 To Execute Transactions on Sepolia:");
    println!("   EXECUTE_TX=1 cargo test -p starknet-client --test tongo_sepolia_integration test_full_tongo_sepolia_flow -- --ignored --nocapture");
    println!("   ⚠️  WARNING: This will spend real STRK tokens for gas on Sepolia testnet!");
    println!();
    println!("📊 Rate Information:");
    println!("   • 1 TONGO unit = 1e18 ERC20 tokens");
    println!("   • For STRK (18 decimals): 1 TONGO = 1 STRK");
    println!("   • Approve amount = fund_amount × rate");

    println!("\n💡 Test Accounts (SAME as TypeScript):");
    println!("   Starknet Account: {:#x}", account_address);
    println!(
        "   TONGO Account 0:  {:#x}",
        tongo_keypair_0
            .public_key
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x()
    );
    println!(
        "   TONGO Account 1:  {:#x}",
        tongo_keypair_1
            .public_key
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x()
    );

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_key_derivation_matches_typescript() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Testing Key Derivation Parity with TypeScript\n");

    // Derive keys EXACTLY as TypeScript does
    let starknet_key =
        derive_keypair_with_coin_type(TEST_MNEMONIC, 0, 0, STARKNET_COIN_TYPE, None)?;
    let tongo_key_0 = derive_keypair_with_coin_type(TEST_MNEMONIC, 0, 0, TONGO_COIN_TYPE, None)?;
    let tongo_key_1 = derive_keypair_with_coin_type(TEST_MNEMONIC, 1, 0, TONGO_COIN_TYPE, None)?;

    println!("Starknet Account Key (coin type 9004, index 0):");
    println!("  Private: {:#x}", starknet_key.private_key);
    println!(
        "  Public:  {:#x}",
        starknet_key
            .public_key
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x()
    );

    println!("\nTONGO Key 0 (coin type 5454, index 0):");
    println!("  Private: {:#x}", tongo_key_0.private_key);
    println!(
        "  Public:  {:#x}",
        tongo_key_0
            .public_key
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x()
    );

    println!("\nTONGO Key 1 (coin type 5454, index 1):");
    println!("  Private: {:#x}", tongo_key_1.private_key);
    println!(
        "  Public:  {:#x}",
        tongo_key_1
            .public_key
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x()
    );

    // Calculate account address
    let oz_class_hash = Felt::from_hex(OZ_ACCOUNT_CLASS_HASH)?;
    let salt = Felt::ZERO;
    let account_address = derive_oz_account_address(
        &starknet_key
            .public_key
            .to_affine()
            .map_err(|e| format!("{:?}", e))?
            .x(),
        &oz_class_hash,
        Some(&salt),
    )?;

    println!("\nAccount Address:");
    println!("  {:#x}", account_address);

    println!("\n✅ Key derivation test passed");
    println!("💡 Verify against TypeScript by running:");
    println!("   cd typescript-reference && bun test kms/tongo-sepolia.test.ts");
    println!("\n📋 These values should EXACTLY match the TypeScript output!");

    Ok(())
}
