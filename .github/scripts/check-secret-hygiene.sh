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

# 3) Ban derive(Debug) on types that embed SecretFelt in production sources.
#    Manual Debug impls are allowed (and required to redact).
while IFS= read -r -d '' path; do
  rel="${path#"$root"/}"
  python3 - "$path" "$rel" <<'PY' || failed=1
import re, sys
path, rel = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
# Strip cfg(test) modules roughly to reduce false positives in unit tests.
text = re.sub(r"#\[cfg\(test\)\][\s\S]*?(?=\n(?:pub\s+)?(?:mod|struct|enum|fn|impl|use|#\[|$))", "\n", text)
pattern = re.compile(
    r"#\[derive\(([^\]]*Debug[^\]]*)\)\]\s*(?:pub\s+)?(?:struct|enum)\s+(\w+)([\s\S]*?)(?=\n(?:#\[|pub\s+|struct\s+|enum\s+|impl\s+|fn\s+|mod\s+|use\s+|$))",
    re.M,
)
bad = []
for m in pattern.finditer(text):
    body = m.group(3)
    if "SecretFelt" in body:
        bad.append(m.group(2))
if bad:
    print(f"::error file={rel}::{rel} derives Debug on type(s) containing SecretFelt: {', '.join(bad)}")
    print("  Implement Debug manually and redact secrets.")
    sys.exit(1)
PY
done < <(find "$root/crates" -path '*/experimental' -prune -o -name '*.rs' -print0)

# 4) Discourage logging helpers around expose_secret in non-test production sources.
#    Advisory only (does not fail CI). Skip crates/*/tests and cfg(test) noise.
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
