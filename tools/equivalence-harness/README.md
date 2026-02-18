# External Rust↔Zig Equivalence Harness

This harness runs deterministic parity checks between:
- `tools/rust-oracle`
- `tools/zig-oracle`

It compares:
- Structured JSON outputs
- Canonical output bytes (`output_bytes_hex`)

## Build

```bash
cargo build --manifest-path tools/rust-oracle/Cargo.toml
zig build-exe \
  --dep kms_zig \
  -Mmain=tools/zig-oracle/main.zig \
  -Mkms_zig=zig/src/root.zig \
  -O ReleaseFast \
  -femit-bin=tools/zig-oracle/zig-oracle
cargo build --manifest-path tools/equivalence-harness/Cargo.toml
```

## Run vectors only

```bash
cargo run --manifest-path tools/equivalence-harness/Cargo.toml -- \
  --rust-bin tools/rust-oracle/target/debug/rust-oracle \
  --zig-bin tools/zig-oracle/zig-oracle \
  --vectors fixtures/vectors/parity/core-vectors.json \
  --mode vectors
```

## Run PR random differential

```bash
cargo run --manifest-path tools/equivalence-harness/Cargo.toml -- \
  --rust-bin tools/rust-oracle/target/debug/rust-oracle \
  --zig-bin tools/zig-oracle/zig-oracle \
  --vectors fixtures/vectors/parity/core-vectors.json \
  --mode random-pr \
  --random-cases 128 \
  --seed 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

Artifacts are written to `tools/equivalence-harness/artifacts` on mismatch.
