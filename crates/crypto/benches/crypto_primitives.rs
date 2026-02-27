//! Benchmarks for low-level cryptographic primitives.
//!
//! This measures the fundamental building blocks:
//! - Scalar multiplication on elliptic curve
//! - Point addition
//! - Scalar arithmetic modulo curve order
//! - Hash operations (Pedersen, challenge generation)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use krusty_kms_crypto::{scalar, StarkCurve};
use starknet_types_core::felt::Felt;

/// Generate a Felt with approximately n bits of entropy.
fn felt_with_bits(bits: u32) -> Felt {
    if bits == 0 {
        return Felt::ZERO;
    }

    let effective_bits = bits.min(252);

    if effective_bits <= 64 {
        let max_val = if effective_bits == 64 {
            u64::MAX
        } else {
            (1u64 << effective_bits) - 1
        };
        return Felt::from(max_val >> 1);
    }

    let bytes_needed = ((effective_bits + 7) / 8) as usize;
    let mut bytes = vec![0u8; 32];

    for i in 0..bytes_needed {
        bytes[32 - bytes_needed + i] = 0xFF;
    }

    let remainder_bits = effective_bits % 8;
    if remainder_bits != 0 {
        bytes[32 - bytes_needed] = (1u8 << remainder_bits) - 1;
    }

    Felt::from_bytes_be_slice(&bytes)
}

/// Benchmark scalar multiplication with the generator.
fn bench_scalar_mul_generator(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar_mul_generator");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];

    for bits in bit_sizes {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, &bits| {
                let scalar = felt_with_bits(bits);
                b.iter(|| {
                    let result = StarkCurve::mul_generator(black_box(&scalar));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark scalar multiplication with arbitrary point.
fn bench_scalar_mul_point(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar_mul_point");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];
    let point = StarkCurve::generator_h(); // Use H generator as arbitrary point

    for bits in bit_sizes {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, &bits| {
                let scalar = felt_with_bits(bits);
                b.iter(|| {
                    let result = StarkCurve::mul(black_box(&scalar), Some(black_box(&point)));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark point addition.
fn bench_point_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_addition");

    let g = StarkCurve::generator();
    let h = StarkCurve::generator_h();

    // Test with different point combinations
    let point_pairs = vec![
        ("G+G", g.clone(), g.clone()),
        ("G+H", g.clone(), h.clone()),
        (
            "2G+3G",
            StarkCurve::mul_generator(&Felt::from(2u64)),
            StarkCurve::mul_generator(&Felt::from(3u64)),
        ),
    ];

    for (name, p1, p2) in point_pairs {
        group.bench_function(name, |b| {
            b.iter(|| {
                let result = StarkCurve::add(black_box(&p1), black_box(&p2));
                black_box(result)
            });
        });
    }

    group.finish();
}

/// Benchmark scalar addition modulo curve order.
fn bench_scalar_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar_add_mod_order");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];

    for bits in bit_sizes {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, &bits| {
                let a = felt_with_bits(bits);
                let b_val = felt_with_bits(bits);
                b.iter(|| {
                    let result = scalar::scalar_add(black_box(&a), black_box(&b_val));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark scalar multiplication modulo curve order.
fn bench_scalar_mul_mod(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar_mul_mod_order");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];

    for bits in bit_sizes {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, &bits| {
                let a = felt_with_bits(bits);
                let b_val = felt_with_bits(bits);
                b.iter(|| {
                    let result = scalar::scalar_mul(black_box(&a), black_box(&b_val));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark Pedersen hash computation.
fn bench_pedersen_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("pedersen_hash");

    use starknet_types_core::hash::{Pedersen, StarkHash};

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];

    for bits in bit_sizes {
        group.throughput(Throughput::Elements(2)); // 2 felts per hash
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, &bits| {
                let a = felt_with_bits(bits);
                let b_val = felt_with_bits(bits);
                b.iter(|| {
                    let result = Pedersen::hash(black_box(&a), black_box(&b_val));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark Fiat-Shamir challenge generation.
fn bench_challenge_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("challenge_generation");

    use krusty_kms_crypto::hash::compute_challenge_single;

    let prefix = Felt::from(42u64);
    let point = StarkCurve::mul_generator(&Felt::from(12345u64));

    group.bench_function("single_point", |b| {
        b.iter(|| {
            let result = compute_challenge_single(black_box(&prefix), black_box(&point));
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark point conversion (projective to affine).
fn bench_point_conversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_conversion");

    let point = StarkCurve::mul_generator(&Felt::from(12345u64));

    group.bench_function("projective_to_affine", |b| {
        b.iter(|| {
            let result = StarkCurve::projective_to_affine(black_box(&point));
            black_box(result)
        });
    });

    let affine = StarkCurve::projective_to_affine(&point).unwrap();

    group.bench_function("affine_to_projective", |b| {
        b.iter(|| {
            let result = StarkCurve::affine_to_projective(black_box(&affine));
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark complete scalar mul + point add sequence (common in proofs).
fn bench_mul_add_sequence(c: &mut Criterion) {
    let mut group = c.benchmark_group("mul_add_sequence");

    let bit_sizes = vec![8, 16, 32, 64, 128, 192, 252];
    let g = StarkCurve::generator();
    let h = StarkCurve::generator_h();

    for bits in bit_sizes {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bits", bits)),
            &bits,
            |b, &bits| {
                let x1 = felt_with_bits(bits);
                let x2 = felt_with_bits(bits);
                b.iter(|| {
                    // This simulates g1^x1 * g2^x2 (common in PoE2)
                    let g_x1 = StarkCurve::mul(black_box(&x1), Some(black_box(&g)));
                    let h_x2 = StarkCurve::mul(black_box(&x2), Some(black_box(&h)));
                    let result = StarkCurve::add(black_box(&g_x1), black_box(&h_x2));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_scalar_mul_generator,
    bench_scalar_mul_point,
    bench_point_addition,
    bench_scalar_add,
    bench_scalar_mul_mod,
    bench_pedersen_hash,
    bench_challenge_generation,
    bench_point_conversion,
    bench_mul_add_sequence,
);

criterion_main!(benches);
