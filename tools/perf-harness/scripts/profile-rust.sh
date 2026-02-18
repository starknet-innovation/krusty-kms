#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUST_BIN="${RUST_BIN:-$ROOT_DIR/target/release/rust-oracle}"
REQ='{"op":"she.range_prove_verify","inputs":{"value":"7","bit_size":8,"prefix":"0x2a"},"rng":{"mode":"deterministic","seed_hex":"0x5555555555555555555555555555555555555555555555555555555555555555","stream":"she-range"}}'

if command -v cargo-flamegraph >/dev/null 2>&1; then
  echo "cargo-flamegraph detected; run with your preferred target command."
  echo "Example: cargo flamegraph -p rust-oracle --release --root -- json <<< '$REQ'"
else
  echo "cargo-flamegraph not installed; install with: cargo install flamegraph"
fi

echo "Raw execution sample:"
printf '%s' "$REQ" | "$RUST_BIN" >/dev/null
