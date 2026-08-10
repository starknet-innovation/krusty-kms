#!/usr/bin/env bash
# Fail if `unsafe` appears outside the allowlisted files.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
allowlist="$root/.github/guardrails/unsafe-allowlist.txt"

if [[ ! -f "$allowlist" ]]; then
  echo "::error::missing unsafe allowlist at $allowlist"
  exit 1
fi

mapfile -t allowed < <(grep -vE '^\s*(#|$)' "$allowlist")
declare -A allow_set=()
for f in "${allowed[@]}"; do
  allow_set["$f"]=1
done

failed=0
while IFS= read -r -d '' path; do
  rel="${path#"$root"/}"
  if [[ -n "${allow_set[$rel]:-}" ]]; then
    continue
  fi
  if grep -nE '\bunsafe\b' "$path" >/dev/null; then
    echo "::error file=$rel::$rel contains \`unsafe\` but is not in .github/guardrails/unsafe-allowlist.txt"
    grep -nE '\bunsafe\b' "$path" | head -n 5 | sed "s/^/  $rel:/"
    failed=1
  fi
done < <(find "$root/crates" -name '*.rs' -not -path '*/target/*' -print0)

# Also ensure allowlisted files still exist (catch renames).
for f in "${allowed[@]}"; do
  if [[ ! -f "$root/$f" ]]; then
    echo "::error::allowlisted unsafe file missing: $f (update the allowlist)"
    failed=1
  fi
done

if (( failed == 1 )); then
  exit 1
fi
echo "unsafe allowlist ok (${#allowed[@]} files)"
