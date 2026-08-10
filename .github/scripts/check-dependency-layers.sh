#!/usr/bin/env bash
# Enforce the production crate dependency DAG.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

python3 - <<'PY'
import re
import sys
from pathlib import Path

root = Path(".")
# Allowed krusty-* path dependencies for each package directory name.
ALLOWED = {
    "common": set(),
    "wallet-api": {"krusty-kms-common"},
    "domain": {"krusty-kms-common"},
    "crypto": {"krusty-kms-common"},
    "kms": {"krusty-kms-common", "krusty-kms-crypto"},
    "sdk": {"krusty-kms-common", "krusty-kms-crypto", "krusty-kms"},
    "client": {
        "krusty-kms-common",
        "krusty-kms-wallet-api",
        "krusty-kms",
        "krusty-kms-sdk",
        "krusty-kms-crypto",
    },
    "gateway": {
        "krusty-kms-domain",
        "krusty-kms-common",
        "krusty-kms",
        "krusty-kms-crypto",
    },
    "oracle": {"krusty-kms-domain", "krusty-kms-gateway", "krusty-kms-common"},
    "wasm": {
        "krusty-kms-sdk",
        "krusty-kms-common",
        "krusty-kms-crypto",
        "krusty-kms",
    },
    "ffi": {
        "krusty-kms",
        "krusty-kms-crypto",
        "krusty-kms-common",
        "krusty-kms-sdk",
    },
}

dep_re = re.compile(r"^(krusty-kms(?:-[a-z0-9-]+)?)\s*=")

failed = 0
for crate_dir, allowed in sorted(ALLOWED.items()):
    cargo = root / "crates" / crate_dir / "Cargo.toml"
    if not cargo.is_file():
        print(f"::error::missing {cargo}")
        failed = 1
        continue
    text = cargo.read_text()
    # Only inspect [dependencies] and target-specific dependency tables,
    # not [dev-dependencies].
    sections = re.split(r"\n(?=\[)", text)
    deps = set()
    for section in sections:
        header = section.split("\n", 1)[0]
        if not (
            header.startswith("[dependencies]")
            or ".dependencies]" in header
        ):
            continue
        if "dev-dependencies" in header:
            continue
        for line in section.splitlines()[1:]:
            m = dep_re.match(line.strip())
            if m:
                deps.add(m.group(1))
    unexpected = sorted(deps - allowed)
    missing_declared = sorted(allowed & deps)  # noqa: F841 - kept for clarity
    if unexpected:
        print(f"::error::crates/{crate_dir} has forbidden krusty-* dependencies: {unexpected}")
        print(f"  allowed: {sorted(allowed) or '(none)'}")
        failed = 1
    else:
        print(f"ok crates/{crate_dir}: {sorted(deps) or '(no krusty-* deps)'}")

if failed:
    sys.exit(1)
print("dependency layering ok")
PY
