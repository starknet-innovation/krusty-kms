# Maintainability guardrails

Executable fitness checks that keep this workspace reviewable. Policy lives in
[`CONTRIBUTING.md`](../CONTRIBUTING.md); enforcement lives in CI.

## What CI enforces

| Check | Script / tool | Failure mode |
| --- | --- | --- |
| File-size ratchet | `.github/scripts/check-file-size-ratchet.sh` | Existing oversized files cannot grow; new files cannot exceed 500 lines |
| PR size | `.github/scripts/check-pr-size.sh` | >400 changed lines or >10 production Rust files without justification |
| Crate dependency DAG | `.github/scripts/check-dependency-layers.sh` | Forbidden `krusty-*` edges |
| `unsafe` allowlist | `.github/scripts/check-unsafe-allowlist.sh` | `unsafe` outside listed files |
| Secret hygiene | `.github/scripts/check-secret-hygiene.sh` | `SecretFelt` Display / `Debug` derive leaks |
| FFI header freeze | `.github/scripts/check-ffi-surface.sh` | `kms.h` drift across packages |
| WASM export freeze | `.github/scripts/check-wasm-exports.sh` | `wasm_bindgen` surface drift |
| Design note | `.github/scripts/check-design-note.sh` | Public API / dep / surface changes without design note |
| Licenses & advisories | `deny.toml` + `cargo-deny` | Disallowed licenses, yanked crates, unknown sources |
| rustdoc links | `cargo doc` + `RUSTDOCFLAGS` | Broken intra-doc links on publishable crates |
| Semver | `cargo-semver-checks` via locked rustdoc JSON | Accidental breaking API changes vs PR base / `main` |
| Cross-compat vectors | `.github/workflows/cross-compat.yml` | Rust↔TS proof drift on touched crates |
| Ignored-test bitrot | `.github/workflows/ignored-integration.yml` | Weekly compile of `--ignored` harnesses |

Workflow entrypoint: [`.github/workflows/guardrails.yml`](../.github/workflows/guardrails.yml).

## Baselines

Committed under [`.github/guardrails/`](../.github/guardrails/):

- `file-size-baseline.json` — ratchet for files already over the soft limit
- `unsafe-allowlist.txt` — files permitted to contain `unsafe`
- `ffi-kms.h.snapshot` / `ffi-kms.h.sha256` — canonical C ABI header
- `wasm-exports.txt` — `wasm_bindgen` export surface

Regenerate after an intentional change:

```bash
bash .github/scripts/regenerate-guardrail-baselines.sh
```

Then include a short design note under `docs/design/` (or a `## Design` section
in the PR body) explaining why the surface grew.

## Local pre-commit

```bash
git config core.hooksPath .githooks
```

The hook runs `cargo fmt` plus the fast fitness scripts (file size, layering,
unsafe allowlist, secret hygiene, FFI/WASM snapshots).

## Design notes

Non-trivial public API, dependency, or boundary changes need:

- `docs/design/YYYY-MM-DD-slug.md`, or
- a `## Design` section in the PR description

Keep notes to 1–2 pages: inputs/outputs, invariants, failure modes, and the
smallest interface that works.

## Dependency DAG

Allowed production edges:

```text
common
 ├── wallet-api
 ├── domain ──► gateway ──► oracle
 ├── crypto ──► kms ──► sdk ──► client
│                │       └──► wasm
│                └──────────► ffi (cabi)
└──────────────► (also used directly by gateway/client/wasm/ffi)
```

`check-dependency-layers.sh` is the source of truth.

## Docs / missing docs trajectory

Publishable crates gate on **broken rustdoc links** today. Prefer documenting
every new `pub` item; a future ratchet may promote `missing_docs` crate-by-crate
once coverage is high enough.
