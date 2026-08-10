#!/usr/bin/env bash
# Run cargo-semver-checks using locked rustdoc JSON for both sides.
# cargo-semver-checks' built-in builders ignore Cargo.lock and can resolve
# semver-compatible but API-incompatible dependency minors (e.g.
# starknet-types-core 0.2.0 -> 0.2.4). Generating rustdoc with --locked
# keeps both sides on the committed dependency graph.
#
# Use --all-features so feature-gated public APIs (e.g. krusty-kms-client's
# `nats` / NatsMultisigCoordinator) appear in rustdoc JSON, matching
# cargo-semver-checks' default feature selection. If a crate fails with
# --all-features (e.g. optional git deps), add a per-crate fallback below.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

baseline_root="${BASELINE_ROOT:-}"
if [[ -z "$baseline_root" ]]; then
  echo "::error::BASELINE_ROOT must point at a git worktree/checkout to compare against"
  exit 1
fi

if ! command -v cargo >/dev/null; then
  echo "::error::cargo is required"
  exit 1
fi
if ! command -v rustup >/dev/null; then
  echo "::error::rustup is required"
  exit 1
fi

# Pin nightly: floating `nightly` can change rustdoc JSON format and break
# cargo-semver-checks compatibility across CI runs.
NIGHTLY_TOOLCHAIN="${NIGHTLY_TOOLCHAIN:-nightly-2026-08-08}"
rustup toolchain install "$NIGHTLY_TOOLCHAIN" --component rust-docs >/dev/null
if ! command -v cargo-semver-checks >/dev/null && ! cargo semver-checks -V >/dev/null 2>&1; then
  cargo install cargo-semver-checks --locked
fi

crates=(
  krusty-kms-common
  krusty-kms-wallet-api
  krusty-kms-domain
  krusty-kms-crypto
  krusty-kms
  krusty-kms-sdk
  krusty-kms-client
  krusty-kms-gateway
)

rustdoc_json() {
  local manifest_root="$1"
  local crate="$2"
  local out_dir="$3"
  mkdir -p "$out_dir"
  (
    cd "$manifest_root"
    # Package name uses hyphens; rustdoc JSON uses underscores.
    local json_name="${crate//-/_}.json"
    if ! cargo "+$NIGHTLY_TOOLCHAIN" rustdoc -p "$crate" --locked --all-features --lib -- \
      -Z unstable-options \
      --output-format json; then
      echo "::error::rustdoc JSON generation failed for $crate in $manifest_root" >&2
      exit 1
    fi
    local src="target/doc/$json_name"
    if [[ ! -f "$src" ]]; then
      src="$(find target/doc -maxdepth 1 -name "$json_name" | head -n1 || true)"
    fi
    if [[ -z "$src" || ! -f "$src" ]]; then
      echo "::error::missing rustdoc json for $crate at $manifest_root (expected target/doc/$json_name)" >&2
      exit 1
    fi
    cp "$src" "$out_dir/$json_name"
    echo "$out_dir/$json_name"
  )
}

current_dir="$(mktemp -d)"
baseline_dir="$(mktemp -d)"
trap 'rm -rf "$current_dir" "$baseline_dir"' EXIT

failed=0
for crate in "${crates[@]}"; do
  echo "::group::semver-checks $crate"
  current_json="$(rustdoc_json "$root" "$crate" "$current_dir")"
  baseline_json="$(rustdoc_json "$baseline_root" "$crate" "$baseline_dir")"
  if ! cargo semver-checks check-release -p "$crate" \
    --current-rustdoc "$current_json" \
    --baseline-rustdoc "$baseline_json"; then
    echo "::error::semver-checks failed for $crate"
    failed=1
  fi
  echo "::endgroup::"
done

exit "$failed"
