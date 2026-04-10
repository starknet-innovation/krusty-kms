//! Transfer Throughput Benchmark
//!
//! This benchmark measures the maximum number of confidential transfers that can
//! be generated per second on the host machine. It tests parallelization scaling
//! by varying the number of concurrent transfer proof generations.
//!
//! The benchmark outputs raw timing data suitable for statistical analysis and
//! visualization with tools like seaborn.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use krusty_kms_common::ElGamalCiphertext;
use krusty_kms_crypto::StarkCurve;
use krusty_kms_sdk::{
    operations::{transfer, TransferParams},
    TongoAccount,
};
use rayon::prelude::*;
use starknet_types_core::felt::Felt;
use std::io::Write;
use std::time::{Duration, Instant};

const TEST_MNEMONIC: &str =
    "habit hope tip crystal because grunt nation idea electric witness alert like";

/// Create a test account with maximum balance.
fn create_test_account() -> TongoAccount {
    let contract_address = Felt::from(123456u64);
    let mut account =
        TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();
    account.set_balance(u128::MAX);
    account
}

/// Create transfer parameters for benchmarking.
fn create_transfer_params(bit_size: usize) -> TransferParams {
    let recipient_key = StarkCurve::mul_generator(&Felt::from(99u64));
    let chain_id = Felt::from_hex("0x534e5f5345504f4c4941").unwrap();
    let tongo_address = Felt::from(123456u64);

    let g = StarkCurve::generator();
    let current_balance = ElGamalCiphertext {
        l: StarkCurve::mul(&Felt::from(u128::MAX), Some(&g)),
        r: StarkCurve::mul(&Felt::from(42u64), Some(&g)),
    };

    // Use a moderate transfer amount
    let amount = (1u128 << (bit_size - 1)) - 1;

    TransferParams {
        recipient_public_key: recipient_key,
        amount,
        nonce: Felt::from(1u64),
        chain_id,
        tongo_address,
        sender_address: Felt::ZERO,

        current_balance,
        bit_size,
        auditor_pub_key: None,
    }
}

/// Benchmark parallel transfer proof generation with different batch sizes.
/// This measures how well the parallelization scales as we increase workload.
fn bench_transfer_throughput_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("transfer_throughput_batch");

    // Use 64-bit for realistic production scenario
    let bit_size: usize = 64;

    // Configure for throughput measurement
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(30));
    group.warm_up_time(Duration::from_secs(5));

    // Get available parallelism
    let num_cpus = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);

    // Test different batch sizes to find optimal parallelization
    let batch_sizes: Vec<usize> = vec![1, 2, 4, 8, 16, 32]
        .into_iter()
        .filter(|&b| b <= num_cpus * 4) // Don't test unreasonably large batches
        .collect();

    for batch_size in batch_sizes {
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("batch_{}", batch_size)),
            &batch_size,
            |b, &batch_size| {
                // Pre-create accounts and params for each parallel transfer
                let accounts: Vec<_> = (0..batch_size).map(|_| create_test_account()).collect();
                let params: Vec<_> = (0..batch_size)
                    .map(|_| create_transfer_params(bit_size))
                    .collect();

                b.iter(|| {
                    // Execute transfers in parallel
                    let results: Vec<_> = accounts
                        .par_iter()
                        .zip(params.par_iter())
                        .map(|(account, params)| {
                            transfer(black_box(account), black_box(params.clone()))
                        })
                        .collect();

                    black_box(results)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark transfer throughput across different bit sizes.
/// This shows how range proof complexity affects throughput.
fn bench_transfer_throughput_bit_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("transfer_throughput_bit_scaling");

    group.sample_size(30);
    group.measurement_time(Duration::from_secs(20));

    // Use batch size equal to CPU count for optimal parallelization
    let batch_size = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);

    let bit_sizes: Vec<usize> = vec![8, 16, 32, 64, 96, 128];

    for bit_size in bit_sizes {
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits_batch{}", bit_size, batch_size)),
            &bit_size,
            |b, &bit_size| {
                let accounts: Vec<_> = (0..batch_size).map(|_| create_test_account()).collect();
                let params: Vec<_> = (0..batch_size)
                    .map(|_| create_transfer_params(bit_size))
                    .collect();

                b.iter(|| {
                    let results: Vec<_> = accounts
                        .par_iter()
                        .zip(params.par_iter())
                        .map(|(account, params)| {
                            transfer(black_box(account), black_box(params.clone()))
                        })
                        .collect();

                    black_box(results)
                });
            },
        );
    }

    group.finish();
}

/// Measure raw transfers per second over a fixed duration.
/// This provides data suitable for probability distribution analysis.
fn bench_sustained_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("transfer_sustained_throughput");

    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_secs(10));

    // Test with 64-bit (common production use case)
    let bit_size: usize = 64;

    let batch_size = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);

    group.throughput(Throughput::Elements(batch_size as u64));
    group.bench_function(format!("64bits_batch{}_sustained", batch_size), |b| {
        let accounts: Vec<_> = (0..batch_size).map(|_| create_test_account()).collect();
        let params: Vec<_> = (0..batch_size)
            .map(|_| create_transfer_params(bit_size))
            .collect();

        b.iter(|| {
            let results: Vec<_> = accounts
                .par_iter()
                .zip(params.par_iter())
                .map(|(account, params)| transfer(black_box(account), black_box(params.clone())))
                .collect();

            black_box(results)
        });
    });

    group.finish();
}

/// Custom benchmark that outputs raw timing data for statistical analysis.
/// This bypasses Criterion to get raw sample data.
fn bench_raw_throughput_samples(_c: &mut Criterion) {
    println!("\n\n========================================");
    println!("RAW THROUGHPUT SAMPLING");
    println!("========================================\n");

    let bit_size: usize = 64;
    let num_samples = 100;
    let batch_size = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);

    println!("Configuration:");
    println!("  Bit size: {}", bit_size);
    println!("  Batch size: {} (parallel transfers)", batch_size);
    println!("  Samples: {}", num_samples);
    println!();

    // Warmup
    println!("Warming up...");
    let account = create_test_account();
    let params = create_transfer_params(bit_size);
    for _ in 0..5 {
        let _ = transfer(&account, params.clone());
    }

    // Collect samples
    println!("Collecting samples...");
    let accounts: Vec<_> = (0..batch_size).map(|_| create_test_account()).collect();
    let params_vec: Vec<_> = (0..batch_size)
        .map(|_| create_transfer_params(bit_size))
        .collect();

    let mut sample_times_ms: Vec<f64> = Vec::with_capacity(num_samples);
    let mut throughputs_per_sec: Vec<f64> = Vec::with_capacity(num_samples);

    for i in 0..num_samples {
        let start = Instant::now();

        let _results: Vec<_> = accounts
            .par_iter()
            .zip(params_vec.par_iter())
            .map(|(account, params)| transfer(account, params.clone()))
            .collect();

        let elapsed = start.elapsed();
        let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
        let tps = batch_size as f64 / elapsed.as_secs_f64();

        sample_times_ms.push(elapsed_ms);
        throughputs_per_sec.push(tps);

        if (i + 1) % 20 == 0 {
            println!("  Progress: {}/{}", i + 1, num_samples);
        }
    }

    // Calculate statistics
    let mean_time: f64 = sample_times_ms.iter().sum::<f64>() / num_samples as f64;
    let mean_tps: f64 = throughputs_per_sec.iter().sum::<f64>() / num_samples as f64;

    let variance: f64 = throughputs_per_sec
        .iter()
        .map(|x| (x - mean_tps).powi(2))
        .sum::<f64>()
        / num_samples as f64;
    let std_dev = variance.sqrt();

    let min_tps = throughputs_per_sec
        .iter()
        .cloned()
        .fold(f64::INFINITY, f64::min);
    let max_tps = throughputs_per_sec
        .iter()
        .cloned()
        .fold(f64::NEG_INFINITY, f64::max);

    // Sort for percentiles
    let mut sorted_tps = throughputs_per_sec.clone();
    sorted_tps.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = sorted_tps[num_samples / 2];
    let p95 = sorted_tps[(num_samples as f64 * 0.95) as usize];
    let p99 = sorted_tps[(num_samples as f64 * 0.99) as usize];

    println!("\n========================================");
    println!("RESULTS");
    println!("========================================\n");
    println!("Transfers per second (TPS):");
    println!("  Mean:     {:.2} TPS", mean_tps);
    println!("  Std Dev:  {:.2} TPS", std_dev);
    println!("  Min:      {:.2} TPS", min_tps);
    println!("  Max:      {:.2} TPS", max_tps);
    println!("  P50:      {:.2} TPS", p50);
    println!("  P95:      {:.2} TPS", p95);
    println!("  P99:      {:.2} TPS", p99);
    println!();
    println!("Batch execution time:");
    println!("  Mean:     {:.2} ms", mean_time);
    println!();

    // Write raw data to file for seaborn analysis
    // Use CARGO_MANIFEST_DIR to get the workspace root, then go to target/
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = std::path::Path::new(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(std::path::Path::new("."));
    let output_dir = workspace_root.join("target/transfer_throughput_data");
    std::fs::create_dir_all(&output_dir).ok();

    let data_file = output_dir.join("raw_samples.csv");
    if let Ok(mut file) = std::fs::File::create(&data_file) {
        writeln!(
            file,
            "sample_id,batch_time_ms,throughput_tps,batch_size,bit_size"
        )
        .ok();
        for (i, (time, tps)) in sample_times_ms
            .iter()
            .zip(throughputs_per_sec.iter())
            .enumerate()
        {
            writeln!(
                file,
                "{},{:.4},{:.4},{},{}",
                i, time, tps, batch_size, bit_size
            )
            .ok();
        }
        println!("Raw data saved to: {}", data_file.display());
    }

    // Write summary JSON
    let summary_file = output_dir.join("summary.json");
    if let Ok(mut file) = std::fs::File::create(&summary_file) {
        let summary = format!(
            r#"{{
  "config": {{
    "bit_size": {},
    "batch_size": {},
    "num_samples": {}
  }},
  "throughput_tps": {{
    "mean": {:.4},
    "std_dev": {:.4},
    "min": {:.4},
    "max": {:.4},
    "p50": {:.4},
    "p95": {:.4},
    "p99": {:.4}
  }},
  "batch_time_ms": {{
    "mean": {:.4}
  }}
}}"#,
            bit_size,
            batch_size,
            num_samples,
            mean_tps,
            std_dev,
            min_tps,
            max_tps,
            p50,
            p95,
            p99,
            mean_time
        );
        file.write_all(summary.as_bytes()).ok();
        println!("Summary saved to: {}", summary_file.display());
    }

    println!("\n========================================\n");
}

/// Comprehensive thread scaling benchmark.
/// Tests how throughput scales with different thread pool sizes.
fn bench_thread_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("transfer_thread_scaling");

    group.sample_size(15);
    group.measurement_time(Duration::from_secs(20));

    let bit_size: usize = 64;
    let max_threads = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);

    // Test with 1, 2, 4, ... up to max threads
    let thread_counts: Vec<usize> = (0..=max_threads.ilog2())
        .map(|i| 1 << i)
        .filter(|&t| t <= max_threads)
        .collect();

    for num_threads in thread_counts {
        // Create a custom thread pool with specific thread count
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap();

        group.throughput(Throughput::Elements(num_threads as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_threads", num_threads)),
            &num_threads,
            |b, &num_threads| {
                let accounts: Vec<_> = (0..num_threads).map(|_| create_test_account()).collect();
                let params: Vec<_> = (0..num_threads)
                    .map(|_| create_transfer_params(bit_size))
                    .collect();

                b.iter(|| {
                    pool.install(|| {
                        let results: Vec<_> = accounts
                            .par_iter()
                            .zip(params.par_iter())
                            .map(|(account, params)| {
                                transfer(black_box(account), black_box(params.clone()))
                            })
                            .collect();

                        black_box(results)
                    })
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_transfer_throughput_batch,
    bench_transfer_throughput_bit_scaling,
    bench_sustained_throughput,
    bench_thread_scaling,
    bench_raw_throughput_samples,
);

criterion_main!(benches);
