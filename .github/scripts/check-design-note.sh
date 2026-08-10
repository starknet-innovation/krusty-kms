#!/usr/bin/env bash
# Require a design note (or PR Design section) when public API surface or
# production dependencies change.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

base_ref="${GUARDRAILS_BASE_REF:-}"
pr_body="${PR_BODY:-}"

if [[ -z "$base_ref" ]]; then
  if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
    base_ref="origin/${GITHUB_BASE_REF}"
  else
    base_ref="origin/main"
  fi
fi

if ! git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
  git fetch --no-tags --depth=1 origin "${GITHUB_BASE_REF:-main}" || true
fi
if ! git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
  echo "::warning::cannot resolve base ref $base_ref; skipping design-note check"
  exit 0
fi

mapfile -t changed < <(git diff --name-only "$base_ref"...HEAD || true)

needs_note=0
reasons=()

for f in "${changed[@]}"; do
  case "$f" in
    crates/*/src/lib.rs)
      if git diff "$base_ref"...HEAD -- "$f" | grep -E '^\+\s*pub\s+' >/dev/null; then
        needs_note=1
        reasons+=("new/changed pub items in $f")
      fi
      ;;
    crates/common/Cargo.toml|crates/wallet-api/Cargo.toml|crates/domain/Cargo.toml|crates/crypto/Cargo.toml|crates/kms/Cargo.toml|crates/sdk/Cargo.toml|crates/client/Cargo.toml|crates/gateway/Cargo.toml)
      if git diff "$base_ref"...HEAD -- "$f" | grep -E '^\+[^+].*=' >/dev/null; then
        # Ignore version-only bumps of existing path deps when possible; still
        # flag newly added dependency lines.
        if git diff "$base_ref"...HEAD -- "$f" | grep -E '^\+[a-zA-Z0-9_-]+\s*=' >/dev/null; then
          needs_note=1
          reasons+=("dependency manifest changed: $f")
        fi
      fi
      ;;
    .github/guardrails/unsafe-allowlist.txt)
      needs_note=1
      reasons+=("unsafe allowlist changed")
      ;;
    .github/guardrails/wasm-exports.txt|.github/guardrails/ffi-kms.h.snapshot|.github/guardrails/ffi-kms.h.sha256)
      needs_note=1
      reasons+=("FFI/WASM surface snapshot changed: $f")
      ;;
  esac
done

if (( needs_note == 0 )); then
  echo "design-note check: no triggering public-surface changes"
  exit 0
fi

has_note=0
for f in "${changed[@]}"; do
  if [[ "$f" == docs/design/* ]]; then
    has_note=1
  fi
done

if grep -qiE '^##[[:space:]]*Design\b|docs/design/' <<<"$pr_body"; then
  has_note=1
fi

if (( has_note == 0 )); then
  echo "::error::public API / dependency / surface-snapshot change requires a design note"
  for r in "${reasons[@]}"; do
    echo "  - $r"
  done
  echo "Add docs/design/YYYY-MM-DD-slug.md or a ## Design section in the PR body."
  exit 1
fi

echo "design-note check ok"
printf '  triggered by:\n'
for r in "${reasons[@]}"; do
  echo "  - $r"
done
