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
#    Keep the scan line-oriented and cheap — avoid catastrophic backtracking on
#    large modules.
while IFS= read -r -d '' path; do
  rel="${path#"$root"/}"
  case "$rel" in
    */tests/*|*/benches/*|*/examples/*) continue ;;
  esac
  python3 - "$path" "$rel" <<'PY' || failed=1
import re, sys
from pathlib import Path

path, rel = Path(sys.argv[1]), sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()
bad = []
i = 0
while i < len(lines):
    line = lines[i]
    if "#[cfg(test)]" in line:
        # Skip the following item roughly (mod/fn/impl/struct/enum).
        i += 1
        while i < len(lines) and not lines[i].strip():
            i += 1
        if i < len(lines) and re.match(r"^\s*(pub\s+)?mod\s+", lines[i]):
            # skip cfg(test) module until matching depth is too hard; jump by
            # indentation heuristic — stop at next top-level item.
            indent = len(lines[i]) - len(lines[i].lstrip())
            i += 1
            while i < len(lines):
                if lines[i].strip() and (len(lines[i]) - len(lines[i].lstrip())) <= indent and not lines[i].lstrip().startswith("#"):
                    break
                i += 1
            continue
    m = re.search(r"#\[derive\(([^\]]*Debug[^\]]*)\)\]", line)
    if not m:
        i += 1
        continue
    # Find the struct/enum declaration within the next few attribute/doc lines.
    j = i + 1
    while j < len(lines) and (
        lines[j].lstrip().startswith("#") or lines[j].lstrip().startswith("//") or not lines[j].strip()
    ):
        j += 1
    if j >= len(lines):
        break
    decl = re.match(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(struct|enum)\s+(\w+)", lines[j])
    if not decl:
        i += 1
        continue
    kind, name = decl.group(1), decl.group(2)
    # Collect body lines until a blank line after a closing brace, or next top-level item.
    body = []
    k = j + 1
    brace = 0
    started = False
    while k < len(lines):
        s = lines[k]
        if "{" in s or "}" in s:
            started = True
        brace += s.count("{") - s.count("}")
        body.append(s)
        k += 1
        if started and brace <= 0:
            break
        if k - j > 400:
            break
    if "SecretFelt" in "\n".join(body):
        bad.append(name)
    i = k

if bad:
    print(f"::error file={rel}::{rel} derives Debug on type(s) containing SecretFelt: {', '.join(bad)}")
    print("  Implement Debug manually and redact secrets.")
    sys.exit(1)
PY
done < <(find "$root/crates" -path '*/experimental' -prune -o -name '*.rs' -print0)

# 4) Discourage logging helpers around expose_secret in non-test production sources.
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
