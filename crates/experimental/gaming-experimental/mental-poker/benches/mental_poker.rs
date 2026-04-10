//! Benchmarks for mental poker operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mental_poker::{
    deck::{CardEncoding, MaskedDeck},
    protocol::MentalPokerProtocol,
    types::Card,
};

fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("player_keygen", |b| {
        b.iter(|| {
            let (pk, sk) = MentalPokerProtocol::player_keygen();
            black_box((pk, sk))
        })
    });
}

fn bench_key_ownership_proof(c: &mut Criterion) {
    let (pk, sk) = MentalPokerProtocol::player_keygen();
    let player_info = b"benchmark_player";

    c.bench_function("prove_key_ownership", |b| {
        b.iter(|| {
            let proof = MentalPokerProtocol::prove_key_ownership(&pk, &sk, player_info).unwrap();
            black_box(proof)
        })
    });

    let proof = MentalPokerProtocol::prove_key_ownership(&pk, &sk, player_info).unwrap();
    c.bench_function("verify_key_ownership", |b| {
        b.iter(|| {
            let valid =
                MentalPokerProtocol::verify_key_ownership(&pk, &proof, player_info).unwrap();
            black_box(valid)
        })
    });
}

fn bench_masking(c: &mut Criterion) {
    let (pk, _sk) = MentalPokerProtocol::player_keygen();
    let card = Card::from_index(1);

    c.bench_function("mask_card", |b| {
        b.iter(|| {
            let (masked, proof) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();
            black_box((masked, proof))
        })
    });

    let (masked, proof) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();
    c.bench_function("verify_mask", |b| {
        b.iter(|| {
            let valid = MentalPokerProtocol::verify_mask(&card, &masked, &pk, &proof).unwrap();
            black_box(valid)
        })
    });
}

fn bench_reveal(c: &mut Criterion) {
    let (pk, sk) = MentalPokerProtocol::player_keygen();
    let card = Card::from_index(1);
    let (masked, _) = MentalPokerProtocol::mask(&card, &pk, None).unwrap();

    c.bench_function("compute_reveal_token", |b| {
        b.iter(|| {
            let (token, proof) =
                MentalPokerProtocol::compute_reveal_token(&masked, &sk, &pk).unwrap();
            black_box((token, proof))
        })
    });

    let (token, proof) = MentalPokerProtocol::compute_reveal_token(&masked, &sk, &pk).unwrap();
    c.bench_function("verify_reveal_token", |b| {
        b.iter(|| {
            let valid =
                MentalPokerProtocol::verify_reveal_token(&masked, &token, &pk, &proof).unwrap();
            black_box(valid)
        })
    });
}

fn bench_deck_operations(c: &mut Criterion) {
    let encoding = CardEncoding::standard_deck();
    let (pk, _sk) = MentalPokerProtocol::player_keygen();

    c.bench_function("create_standard_deck", |b| {
        b.iter(|| {
            let deck = MaskedDeck::standard(&encoding, &pk).unwrap();
            black_box(deck)
        })
    });

    let deck = MaskedDeck::standard(&encoding, &pk).unwrap();
    c.bench_function("shuffle_deck", |b| {
        b.iter(|| {
            let shuffled = deck.shuffle(&pk).unwrap();
            black_box(shuffled)
        })
    });
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_key_ownership_proof,
    bench_masking,
    bench_reveal,
    bench_deck_operations,
);
criterion_main!(benches);
