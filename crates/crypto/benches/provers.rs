//! Comprehensive benchmarks for cryptographic provers.
//!
//! This benchmark suite measures how proof generation and verification time
//! scales with input bit size. We test:
//! - PoE (Proof of Exponentiation): Single-variable proofs
//! - PoE2 (Two-variable PoE): Okamoto's protocol with two generators
//! - ElGamal: Encryption with zero-knowledge proofs
//!
//! Input sizes tested: 8, 16, 32, 64, 128, 192, 252 bits

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use krusty_kms_crypto::{ElGamal, ProofOfExponentiation, ProofOfExponentiation2, StarkCurve};
use starknet_types_core::felt::Felt;

/// Generate a Felt with approximately n bits of entropy.
fn felt_with_bits(bits: u32) -> Felt {
    if bits == 0 {
        return Felt::ZERO;
    }

    // Stark field is ~252 bits, so cap at that
    let effective_bits = bits.min(252);

    // For small bit sizes, use simple values
    if effective_bits <= 64 {
        let max_val = if effective_bits == 64 {
            u64::MAX
        } else {
            (1u64 << effective_bits) - 1
        };
        return Felt::from(max_val >> 1); // Use half of max to avoid edge cases
    }

    // For larger bit sizes, construct from bytes
    let bytes_needed = ((effective_bits + 7) / 8) as usize;
    let mut bytes = vec![0u8; 32];

    // Fill the required bytes with 0xFF to get maximum value
    for i in 0..bytes_needed {
        bytes[32 - bytes_needed + i] = 0xFF;
    }

    // Adjust the last byte to get exact bit count
    let remainder_bits = effective_bits % 8;
    if remainder_bits != 0 {
        bytes[32 - bytes_needed] = (1u8 << remainder_bits) - 1;
    }

    Felt::from_bytes_be_slice(&bytes)
}

/// Benchmark PoE proof generation with varying input bit sizes.
fn bench_poe_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("poe_prove");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];
    let prefix = Felt::from(42u64);

    for bits in bit_sizes {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, &bits| {
                let x = felt_with_bits(bits);
                b.iter(|| {
                    let result = ProofOfExponentiation::prove(black_box(&x), black_box(&prefix));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark PoE proof verification with varying input bit sizes.
fn bench_poe_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("poe_verify");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];
    let prefix = Felt::from(42u64);

    for bits in bit_sizes {
        let x = felt_with_bits(bits);
        let (y, proof) = ProofOfExponentiation::prove(&x, &prefix).unwrap();

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, _bits| {
                b.iter(|| {
                    let result = ProofOfExponentiation::verify(
                        black_box(&y),
                        black_box(&proof),
                        black_box(&prefix),
                    );
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark PoE2 proof generation with varying input bit sizes.
fn bench_poe2_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("poe2_prove");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];
    let prefix = Felt::from(42u64);
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();

    for bits in bit_sizes {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, &bits| {
                let x1 = felt_with_bits(bits);
                let x2 = felt_with_bits(bits);
                b.iter(|| {
                    let result = ProofOfExponentiation2::prove(
                        black_box(&x1),
                        black_box(&x2),
                        black_box(&g1),
                        black_box(&g2),
                        black_box(&prefix),
                    );
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark PoE2 proof verification with varying input bit sizes.
fn bench_poe2_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("poe2_verify");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];
    let prefix = Felt::from(42u64);
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();

    for bits in bit_sizes {
        let x1 = felt_with_bits(bits);
        let x2 = felt_with_bits(bits);
        let (y, proof) = ProofOfExponentiation2::prove(&x1, &x2, &g1, &g2, &prefix).unwrap();

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, _bits| {
                b.iter(|| {
                    let result = ProofOfExponentiation2::verify(
                        black_box(&y),
                        black_box(&g1),
                        black_box(&g2),
                        black_box(&proof),
                        black_box(&prefix),
                    );
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark ElGamal encryption with varying message bit sizes.
fn bench_elgamal_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("elgamal_encrypt");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];
    let prefix = Felt::from(42u64);

    // Fixed keypair for encryption
    let sk = Felt::from(12345u64);
    let pk = StarkCurve::mul_generator(&sk);

    for bits in bit_sizes {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, &bits| {
                let message = felt_with_bits(bits);
                let random = felt_with_bits(128); // Use 128-bit randomness
                b.iter(|| {
                    let result = ElGamal::encrypt(
                        black_box(&message),
                        black_box(&pk),
                        black_box(&random),
                        black_box(&prefix),
                    );
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark ElGamal verification with varying message bit sizes.
fn bench_elgamal_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("elgamal_verify");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];
    let prefix = Felt::from(42u64);

    let sk = Felt::from(12345u64);
    let pk = StarkCurve::mul_generator(&sk);

    for bits in bit_sizes {
        let message = felt_with_bits(bits);
        let random = felt_with_bits(128);
        let encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, _bits| {
                b.iter(|| {
                    let result = ElGamal::verify(
                        black_box(&encryption.l),
                        black_box(&encryption.r),
                        black_box(&pk),
                        black_box(&encryption.proof),
                        black_box(&prefix),
                    );
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark complete PoE prove + verify cycle.
fn bench_poe_full_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("poe_full_cycle");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];
    let prefix = Felt::from(42u64);

    for bits in bit_sizes {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, &bits| {
                let x = felt_with_bits(bits);
                b.iter(|| {
                    let (y, proof) =
                        ProofOfExponentiation::prove(black_box(&x), black_box(&prefix)).unwrap();
                    let valid = ProofOfExponentiation::verify(
                        black_box(&y),
                        black_box(&proof),
                        black_box(&prefix),
                    )
                    .unwrap();
                    black_box(valid)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark complete PoE2 prove + verify cycle.
fn bench_poe2_full_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("poe2_full_cycle");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];
    let prefix = Felt::from(42u64);
    let g1 = StarkCurve::generator();
    let g2 = StarkCurve::generator_h();

    for bits in bit_sizes {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, &bits| {
                let x1 = felt_with_bits(bits);
                let x2 = felt_with_bits(bits);
                b.iter(|| {
                    let (y, proof) = ProofOfExponentiation2::prove(
                        black_box(&x1),
                        black_box(&x2),
                        black_box(&g1),
                        black_box(&g2),
                        black_box(&prefix),
                    )
                    .unwrap();
                    let valid = ProofOfExponentiation2::verify(
                        black_box(&y),
                        black_box(&g1),
                        black_box(&g2),
                        black_box(&proof),
                        black_box(&prefix),
                    )
                    .unwrap();
                    black_box(valid)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_poe_prove,
    bench_poe_verify,
    bench_poe_full_cycle,
    bench_poe2_prove,
    bench_poe2_verify,
    bench_poe2_full_cycle,
    bench_elgamal_encrypt,
    bench_elgamal_verify,
);

criterion_main!(benches);
