# Perf Harness

Performance harness for Rust vs Zig KMS/SHE/Tongo operations.

## What it does
- Runs a curated benchmark corpus covering:
  - `mnemonic->seed`
  - `derive keypair`
  - `pedersen hash`
  - `poseidon hash many`
  - `curve mul generator`
  - `poe prove+verify`
  - `elgamal encrypt+verify+decrypt`
  - `range prove+verify`
  - `audit prove+verify`
  - `tongo fund/transfer/rollover/withdraw/ragequit`
- Produces both JSON and Markdown reports with median, p95, stddev and commit SHA.

## Usage

```bash
cargo run -p perf-harness --manifest-path /Users/theodorepender/Coding/kms/Cargo.toml -- \
  --rust-bin /Users/theodorepender/Coding/kms/target/release/rust-oracle \
  --zig-bin /Users/theodorepender/Coding/kms/tools/zig-oracle/zig-oracle-release \
  --vectors /Users/theodorepender/Coding/kms/fixtures/vectors/parity/core-vectors.json \
  --out-dir /Users/theodorepender/Coding/kms/tools/perf-harness/results \
  --samples 5 \
  --warmup 1
```

Outputs:
- `results/perf-<unix>.json`
- `results/perf-<unix>.md`
- `results/latest.json`
- `results/latest.md`

## Notes
- The current harness uses oracle executables as runners to ensure equivalent call surfaces.
- Synthetic Tongo perf inputs use `bit_size=16` so `transfer`/`withdraw` execute instead of failing range bounds.
- Measurements include process startup and JSON I/O overhead for each sample; use profile scripts for deeper in-process hotspot analysis.

## Profiling Scripts
- `scripts/profile-rust.sh`
- `scripts/profile-zig.sh`

These scripts provide starting points for flamegraph/profile capture on Linux/macOS.
