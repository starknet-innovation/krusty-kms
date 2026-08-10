#!/usr/bin/env bash
# Lightweight secret-handling hygiene checks for production crates.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
failed=0

# 1) SecretFelt must not implement Display (would encourage logging secrets).
if grep -R --include='*.rs' -nE 'impl\s+(core::fmt::|std::fmt::)?Display\s+for\s+SecretFelt' \
  "$root/crates/common" >/dev/null; then
  echo "::error::SecretFelt must not implement Display"
  failed=1
fi

# 2) SecretFelt Debug must stay redacted (smoke check on source).
if ! grep -n 'SecretFelt(\*\*\*)' "$root/crates/common/src/secret_felt.rs" >/dev/null; then
  echo "::error::SecretFelt Debug redaction marker missing"
  failed=1
fi

# Advisory only: discourage println of exposed secrets outside tests.
while IFS= read -r match; do
  echo "::warning::$match"
done < <(grep -R --include='*.rs' -nE 'println!.*expose_secret|eprintln!.*expose_secret' \
  "$root/crates" \
  --exclude-dir experimental \
  --exclude-dir target \
  --exclude-dir tests \
  || true)

if (( failed == 1 )); then
  exit 1
fi
echo "secret hygiene ok"
