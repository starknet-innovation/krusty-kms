//! End-to-end benchmarks for TONGO protocol operations.
//!
//! This measures the complete operation flows:
//! - Fund: Deposit STRK into confidential balance
//! - Transfer: Send confidential STRK to another account
//! - Rollover: Activate pending balance
//! - Withdraw: Exit confidential balance to public STRK
//!
//! We test how operation time scales with input bit sizes (amount complexity).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use krusty_kms_common::ElGamalCiphertext;
use krusty_kms_crypto::StarkCurve;
use krusty_kms_sdk::{
    operations::{
        fund, ragequit, rollover, transfer, withdraw, FundParams, RagequitParams, RolloverParams,
        TransferParams, WithdrawParams,
    },
    TongoAccount,
};
use starknet_types_core::felt::Felt;

const TEST_MNEMONIC: &str =
    "habit hope tip crystal because grunt nation idea electric witness alert like";

/// Create a test account with a specific balance.
fn create_account_with_balance(balance: u128, pending: u128) -> TongoAccount {
    let contract_address = Felt::from(123456u64);
    let mut account =
        TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();
    account.state.balance = balance;
    account.state.pending_balance = pending;
    account
}

/// Generate amount for a specific bit size (near maximum value for that bit size).
fn amount_for_bits(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX >> (128 - bits)
    } else {
        (1u128 << bits) - 1
    }
}

/// Benchmark fund operation with varying bit sizes.
/// Tests how performance scales as the complexity of amounts increases.
fn bench_fund(c: &mut Criterion) {
    let mut group = c.benchmark_group("fund_operation");

    // Test with different bit sizes to measure scaling
    let bit_sizes: Vec<u32> = vec![8, 16, 32, 64, 96, 128];

    let account = create_account_with_balance(0, 0);
    let chain_id = Felt::from_hex("0x534e5f5345504f4c4941").unwrap();
    let tongo_address = Felt::from(123456u64);

    // Mock current balance cipher (empty for fund)
    let g = StarkCurve::generator();
    let current_balance = ElGamalCiphertext {
        l: g.clone(),
        r: g.clone(),
    };

    for bits in bit_sizes {
        let amount = amount_for_bits(bits);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &amount,
            |b, &amount| {
                let params = FundParams {
                    amount,
                    nonce: Felt::from(1u64),
                    chain_id,
                    tongo_address,
                    auditor_pub_key: None,
                    current_balance: current_balance.clone(),
                };
                b.iter(|| {
                    let result = fund(black_box(&account), black_box(params.clone()));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark transfer operation with varying bit sizes.
/// Tests the full transfer proof generation including range proofs for:
/// 1. Transfer amount (proves amount is in [0, 2^bit_size - 1])
/// 2. Leftover balance (proves remaining balance is valid)
fn bench_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("transfer_operation");

    // Sample count for statistical significance
    group.sample_size(50);
    // Measurement time per run (in seconds)
    group.measurement_time(std::time::Duration::from_secs(10));

    let bit_sizes: Vec<u32> = vec![8, 16, 32, 64, 96, 128];

    let account = create_account_with_balance(u128::MAX, 0); // Account with maximum balance for 128-bit test
    let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
    let chain_id = Felt::from_hex("0x534e5f5345504f4c4941").unwrap(); // SN_SEPOLIA
    let tongo_address = Felt::from(123456u64);

    // Mock current balance cipher
    let g = StarkCurve::generator();
    let current_balance = ElGamalCiphertext {
        l: StarkCurve::mul(&Felt::from(u128::MAX), Some(&g)),
        r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
    };

    for bits in bit_sizes {
        let amount = amount_for_bits(bits);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &amount,
            |b, &amount| {
                let params = TransferParams {
                    recipient_public_key: recipient_key.clone(),
                    amount,
                    nonce: Felt::from(1u64),
                    chain_id,
                    tongo_address,
                    current_balance: current_balance.clone(),
                    bit_size: bits as usize,
                    auditor_pub_key: None, // No audit for pure performance measurement
                };
                b.iter(|| {
                    let result = transfer(black_box(&account), black_box(params.clone()));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark rollover operation with varying bit sizes for pending balances.
fn bench_rollover(c: &mut Criterion) {
    let mut group = c.benchmark_group("rollover_operation");

    let bit_sizes: Vec<u32> = vec![8, 16, 32, 64, 96, 128];
    let chain_id = Felt::from_hex("0x534e5f5345504f4c4941").unwrap();
    let tongo_address = Felt::from(123456u64);

    for bits in bit_sizes {
        let pending = amount_for_bits(bits);
        let current = amount_for_bits(bits / 2); // Current balance at half the bits
        let account = create_account_with_balance(current, pending);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &pending,
            |b, _pending| {
                let params = RolloverParams {
                    nonce: Felt::from(1u64),
                    chain_id,
                    tongo_address,
                };
                b.iter(|| {
                    let result = rollover(black_box(&account), black_box(params.clone()));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark withdraw operation with varying bit sizes.
fn bench_withdraw(c: &mut Criterion) {
    let mut group = c.benchmark_group("withdraw_operation");

    // Sample count for statistical significance (withdraw has range proofs)
    group.sample_size(50);
    group.measurement_time(std::time::Duration::from_secs(10));

    let bit_sizes: Vec<u32> = vec![8, 16, 32, 64, 96, 128];

    let account = create_account_with_balance(u128::MAX, 0); // Account with maximum balance for 128-bit test
    let recipient_address = Felt::from(999u64);
    let chain_id = Felt::from_hex("0x534e5f5345504f4c4941").unwrap();
    let tongo_address = Felt::from(123456u64);

    // Create a VALID encrypted balance cipher
    // cipher = encrypt(balance, randomness, public_key)
    // L = g^balance + y^randomness
    // R = g^randomness
    let g = StarkCurve::generator();
    let y = &account.keypair.public_key;
    let randomness = Felt::from(42u64);
    let current_balance = ElGamalCiphertext {
        l: {
            let g_balance = StarkCurve::mul(&Felt::from(u128::MAX), Some(&g));
            let y_r = StarkCurve::mul(&randomness, Some(y));
            StarkCurve::add(&g_balance, &y_r)
        },
        r: StarkCurve::mul(&randomness, Some(&g)),
    };

    for bits in bit_sizes {
        let amount = amount_for_bits(bits);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &amount,
            |b, &amount| {
                let params = WithdrawParams {
                    recipient_address,
                    amount,
                    nonce: Felt::from(1u64),
                    chain_id,
                    tongo_address,
                    current_balance: current_balance.clone(),
                    bit_size: bits as usize,
                    auditor_key: None, // No audit for pure performance measurement
                };
                b.iter(|| {
                    let result = withdraw(black_box(&account), black_box(params.clone()));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark ragequit operation with varying bit sizes.
fn bench_ragequit(c: &mut Criterion) {
    let mut group = c.benchmark_group("ragequit_operation");

    let bit_sizes: Vec<u32> = vec![8, 16, 32, 64, 96, 128];

    let recipient_address = Felt::from(999u64);
    let chain_id = Felt::from_hex("0x534e5f5345504f4c4941").unwrap();
    let tongo_address = Felt::from(123456u64);

    let g = StarkCurve::generator();

    for bits in bit_sizes {
        let amount = amount_for_bits(bits);
        let account = create_account_with_balance(amount, 0);

        // Mock current balance cipher for the full balance
        let current_balance = ElGamalCiphertext {
            l: StarkCurve::mul(&Felt::from(amount), Some(&g)),
            r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
        };

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &amount,
            |b, &_amount| {
                let params = RagequitParams {
                    recipient_address,
                    nonce: Felt::from(1u64),
                    chain_id,
                    tongo_address,
                    current_balance: current_balance.clone(),
                    auditor_key: None, // No audit for pure performance measurement
                };
                b.iter(|| {
                    let result = ragequit(black_box(&account), black_box(params.clone()));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark complete user flow with varying bit sizes.
fn bench_complete_flow(c: &mut Criterion) {
    let mut group = c.benchmark_group("complete_flow");

    let bit_sizes: Vec<u32> = vec![8, 16, 32, 64];
    let contract_address = Felt::from(123456u64);
    let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
    let recipient_address = Felt::from(999u64);

    for bits in bit_sizes {
        let amount = amount_for_bits(bits);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &amount,
            |b, &amount| {
                b.iter(|| {
                    // Create fresh account
                    let mut account =
                        TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None)
                            .unwrap();

                    let chain_id = Felt::from_hex("0x534e5f5345504f4c4941").unwrap();
                    let g = StarkCurve::generator();
                    let current_balance = ElGamalCiphertext {
                        l: g.clone(),
                        r: g.clone(),
                    };

                    // Fund
                    let fund_params = FundParams {
                        amount,
                        nonce: Felt::from(1u64),
                        chain_id,
                        tongo_address: contract_address,
                        auditor_pub_key: None,
                        current_balance: current_balance.clone(),
                    };
                    let _fund_proof = fund(black_box(&account), black_box(fund_params)).unwrap();

                    // Update state (simulate on-chain execution)
                    account.state.pending_balance += amount;

                    // Rollover
                    let rollover_params = RolloverParams {
                        nonce: Felt::from(1u64),
                        chain_id,
                        tongo_address: contract_address,
                    };
                    let _rollover_proof =
                        rollover(black_box(&account), black_box(rollover_params)).unwrap();

                    // Update state
                    account.state.balance += account.state.pending_balance;
                    account.state.pending_balance = 0;

                    // Mock updated balance cipher
                    let updated_balance = ElGamalCiphertext {
                        l: StarkCurve::mul(&Felt::from(amount), Some(&g)),
                        r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
                    };

                    // Transfer
                    let transfer_params = TransferParams {
                        recipient_public_key: recipient_key.clone(),
                        amount: amount / 2,
                        nonce: Felt::from(2u64),
                        chain_id,
                        tongo_address: contract_address,
                        current_balance: updated_balance.clone(),
                        bit_size: bits as usize,
                        auditor_pub_key: None,
                    };
                    let _transfer_proof =
                        transfer(black_box(&account), black_box(transfer_params)).unwrap();

                    // Update state
                    account.state.balance -= amount / 2;

                    // Withdraw
                    let leftover_balance = ElGamalCiphertext {
                        l: StarkCurve::mul(&Felt::from(amount / 4), Some(&g)),
                        r: StarkCurve::mul(&Felt::from(43u64), Some(&g)),
                    };
                    let withdraw_params = WithdrawParams {
                        recipient_address,
                        amount: amount / 4,
                        nonce: Felt::from(3u64),
                        chain_id,
                        tongo_address: contract_address,
                        current_balance: leftover_balance,
                        bit_size: bits as usize,
                        auditor_key: None,
                    };
                    let _withdraw_proof =
                        withdraw(black_box(&account), black_box(withdraw_params)).unwrap();

                    black_box(())
                });
            },
        );
    }

    group.finish();
}

/// Benchmark account derivation from mnemonic.
fn bench_account_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_derivation");

    let contract_address = Felt::from(123456u64);

    group.bench_function("derive_from_mnemonic", |b| {
        b.iter(|| {
            let result = TongoAccount::from_mnemonic(
                black_box(TEST_MNEMONIC),
                black_box(0),
                black_box(0),
                black_box(contract_address),
                None,
            );
            black_box(result)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_fund,
    bench_transfer,
    bench_rollover,
    bench_withdraw,
    bench_ragequit,
    bench_complete_flow,
    bench_account_derivation,
);

criterion_main!(benches);
