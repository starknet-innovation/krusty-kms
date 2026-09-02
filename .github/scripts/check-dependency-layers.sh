#!/usr/bin/env bash
# Enforce the crate dependency DAG. Fail closed on crates missing from policy.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
export PYTHONPATH="$root/.github/scripts${PYTHONPATH:+:$PYTHONPATH}"

python3 - <<'PY'
import sys
from pathlib import Path

from lib.surfaces import krusty_deps_from_cargo_toml

root = Path(".")

# Keys are paths relative to crates/ (top-level dirs, or experimental package dirs).
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
    # The mobile ABI is deliberately narrower than "ffi": no sdk, and nothing
    # that could pull private-key derivation or software signing into a phone
    # binary. See docs/design/2026-09-01-mobile-c-abi.md.
    "ffi-mobile": {
        "krusty-kms",
        "krusty-kms-crypto",
    },
    # Excluded from the workspace, but still in-tree — keep it on the policy list.
    "controller": {"krusty-kms-common", "krusty-kms-wallet-api"},
    "experimental/gaming-experimental/mental-poker": {
        "krusty-kms-common",
        "krusty-kms-crypto",
    },
    "experimental/gaming-experimental/mental-poker-wasm": {
        "krusty-kms-common",
        "krusty-kms-crypto",
    },
    "experimental/gaming-experimental/qb-game": {"krusty-kms-crypto"},
}

failed = 0

# Discover every crates/**/Cargo.toml package and require policy coverage.
found: set[str] = set()
for cargo in sorted((root / "crates").rglob("Cargo.toml")):
    rel = cargo.parent.relative_to(root / "crates").as_posix()
    found.add(rel)

unknown = sorted(found - set(ALLOWED))
if unknown:
    print(f"::error::crates not covered by the layering policy: {unknown}")
    failed = 1

missing_policy = sorted(set(ALLOWED) - found)
if missing_policy:
    print(f"::error::layering policy references missing crates: {missing_policy}")
    failed = 1

for crate_dir, allowed in sorted(ALLOWED.items()):
    cargo = root / "crates" / crate_dir / "Cargo.toml"
    if not cargo.is_file():
        continue
    deps = krusty_deps_from_cargo_toml(cargo.read_text())
    unexpected = sorted(deps - allowed)
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
