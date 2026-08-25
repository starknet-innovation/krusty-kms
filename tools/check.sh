#!/usr/bin/env bash
# Canonical local validation entrypoint. Keep the commands here aligned with
# .github/workflows/rust.yml so contributors and agents exercise the same paths.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

usage() {
  cat <<'EOF'
Usage: bash tools/check.sh <mode>

Modes:
  quick       Formatting plus fast maintainability guardrails
  rust        Formatting, Clippy, examples, and native Rust tests
  wasm        WASM boundary tests under Node
  all         rust + guardrails + wasm (standard pre-handoff check)
  fmt         Check Rust formatting
  lint        Run the workspace and NATS-feature Clippy checks
  lint-complexity
              Run the workspace and NATS-feature Clippy cognitive-complexity checks
  examples    Check the maintained examples
  test        Run native workspace and NATS-feature tests
  guardrails  Run fast local maintainability fitness checks
  help        Show this message

The WASM crate is deliberately excluded from native cargo tests and is tested
only through the wasm mode.
EOF
}

run() {
  printf '\n==> %s\n' "$*"
  "$@"
}

check_fmt() {
  run cargo fmt --all -- --check
}

check_lint_with() {
  local lint_args=("$@")
  run cargo clippy --workspace --all-targets --locked -- -D warnings "${lint_args[@]}"
  run cargo clippy -p krusty-kms-client --all-targets --features nats --locked -- -D warnings "${lint_args[@]}"
}

check_lint() {
  check_lint_with
}

check_cognitive_lint() {
  check_lint_with -D clippy::cognitive_complexity
}

check_examples() {
  run cargo check -p krusty-kms --examples --locked
  run cargo check -p krusty-kms-sdk --examples --locked
}

check_tests() {
  run cargo test --workspace --locked --exclude krusty-kms-wasm
  run cargo test -p krusty-kms-client --locked --features nats
}

check_guardrails() {
  if ((BASH_VERSINFO[0] < 4)); then
    echo "guardrails need bash >= 4 (e.g. brew install bash)" >&2
    exit 1
  fi

  local scripts=(
    .github/scripts/check-file-size-ratchet.sh
    .github/scripts/check-dependency-layers.sh
    .github/scripts/check-unsafe-allowlist.sh
    .github/scripts/check-secret-hygiene.sh
    .github/scripts/check-ffi-surface.sh
    .github/scripts/check-wasm-exports.sh
  )

  local script
  for script in "${scripts[@]}"; do
    run bash "$script"
  done

  run python3 .github/scripts/check-code-complexity.py
}

check_wasm() {
  run wasm-pack test --node crates/wasm
}

check_rust() {
  check_fmt
  check_lint
  check_examples
  check_tests
}

mode="${1:-help}"
if (($# > 1)); then
  usage >&2
  exit 2
fi

case "$mode" in
  quick)
    check_fmt
    check_guardrails
    ;;
  rust)
    check_rust
    ;;
  wasm)
    check_wasm
    ;;
  all)
    check_rust
    check_guardrails
    check_wasm
    ;;
  fmt)
    check_fmt
    ;;
  lint)
    check_lint
    ;;
  lint-complexity)
    check_cognitive_lint
    ;;
  examples)
    check_examples
    ;;
  test)
    check_tests
    ;;
  guardrails)
    check_guardrails
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "unknown mode: $mode" >&2
    usage >&2
    exit 2
    ;;
esac
