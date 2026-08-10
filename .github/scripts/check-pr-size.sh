#!/usr/bin/env bash
# Soft size gate for Rust production sources in a PR.
# Counts added+deleted lines and touched files under crates/** (excluding
# experimental/). Large PRs must include a justification marker in the PR body.
#
# Scope trade-off: this intentionally measures production Rust sources only,
# not guardrail shell/Python. Documented in docs/maintainability-guardrails.md.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

max_lines="${PR_MAX_LINES:-400}"
max_files="${PR_MAX_FILES:-10}"
base_ref="${GUARDRAILS_BASE_REF:-}"
pr_body="${PR_BODY:-}"
fail_closed="${GUARDRAILS_FAIL_CLOSED:-}"

if [[ -z "$base_ref" ]]; then
  if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
    base_ref="origin/${GITHUB_BASE_REF}"
  else
    base_ref="origin/main"
  fi
fi

if [[ -z "$fail_closed" && -n "${GITHUB_BASE_REF:-}" ]]; then
  fail_closed=1
fi

if ! git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
  echo "base ref $base_ref unavailable; fetching full history for triple-dot diff..."
  git fetch --no-tags origin "${GITHUB_BASE_REF:-main}"
fi

if ! git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
  if [[ "$fail_closed" == "1" ]]; then
    echo "::error::cannot resolve base ref $base_ref; PR size check fails closed"
    exit 1
  fi
  echo "::warning::cannot resolve base ref $base_ref; skipping PR size check"
  exit 0
fi

mapfile -t files < <(git diff --name-only "$base_ref"...HEAD -- 'crates/**/*.rs' \
  | grep -v '/experimental/' || true)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "PR size check: no production Rust sources changed"
  exit 0
fi

changed_lines="$(git diff --numstat "$base_ref"...HEAD -- "${files[@]}" \
  | awk '{ add+=$1; del+=$2 } END { print add+del+0 }')"

file_count="${#files[@]}"
echo "PR touches $file_count production Rust file(s), ~$changed_lines changed line(s)"

justified=0
if grep -qiE 'Why this (PR|file) is (large|long)|GUARDRAILS_ALLOW_LARGE_PR' <<<"$pr_body"; then
  justified=1
fi

failed=0
if (( file_count > max_files )) && (( justified == 0 )); then
  echo "::error::PR touches $file_count production Rust files (limit $max_files)."
  echo "Split the change or add a 'Why this PR is large' section to the PR body."
  failed=1
fi
if (( changed_lines > max_lines )) && (( justified == 0 )); then
  echo "::error::PR changes ~$changed_lines production Rust lines (limit $max_lines)."
  echo "Split the change or add a 'Why this PR is large' section to the PR body."
  failed=1
fi

if (( failed == 1 )); then
  exit 1
fi

if (( justified == 1 )) && { (( file_count > max_files )) || (( changed_lines > max_lines )); }; then
  echo "::warning::large PR accepted because justification marker was present"
fi

echo "PR size check ok"
