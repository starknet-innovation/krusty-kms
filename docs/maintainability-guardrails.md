# Maintainability guardrails

Executable fitness checks that keep this workspace reviewable. Policy lives in
[`CONTRIBUTING.md`](../CONTRIBUTING.md); enforcement lives in CI.

## What CI enforces

| Check | Script / tool | Failure mode |
| --- | --- | --- |
| File-size ratchet | `.github/scripts/check-file-size-ratchet.sh` | Existing oversized files cannot grow; new files cannot exceed 500 lines |
| PR size | `.github/scripts/check-pr-size.sh` | >400 changed lines or >10 production Rust files without justification |
| Crate dependency DAG | `.github/scripts/check-dependency-layers.sh` | Forbidden `krusty-*` edges; unknown crates fail closed |
| `unsafe` policy | crate attrs + `.github/scripts/check-unsafe-allowlist.sh` | Missing `forbid`/`deny`/`allow(unsafe_code)`; stray `unsafe` |
| Secret hygiene | `.github/scripts/check-secret-hygiene.sh` | `SecretFelt` Display / missing Debug redaction |
| Release action pinning | `.github/scripts/check-publish-actions-pinned.sh` | Mutable refs, local actions, aliases, or invalid YAML in trusted publishing workflows |
| FFI header freeze | `.github/scripts/check-ffi-surface.sh` | `kms.h` drift across packages |
| WASM export freeze | `.github/scripts/check-wasm-exports.sh` | `wasm_bindgen` surface drift |
| Design note | `.github/scripts/check-design-note.sh` | Public API / dep / surface changes without design note |
| Licenses & advisories | `deny.toml` + `cargo-deny` | Disallowed licenses, yanked crates, unknown sources |
| rustdoc links | `cargo doc` + `RUSTDOCFLAGS` | Broken intra-doc links on publishable crates |
| Semver | `cargo-semver-checks` via locked rustdoc JSON | Accidental breaking API changes vs PR base / `main` |
| Cross-compat vectors | `.github/workflows/cross-compat.yml` | Rust↔TS proof drift on touched crates |
| Ignored-test bitrot | `.github/workflows/ignored-integration.yml` | Weekly compile of `--ignored` harnesses |

Workflow entrypoint: [`.github/workflows/guardrails.yml`](../.github/workflows/guardrails.yml).
Push runs are limited to `main` (PR events cover branches) with a concurrency group.

### npm trusted-publishing prerequisites

The `npm` GitHub environment is a required security control, not optional release
metadata. Repository administrators must configure it with at least one required
reviewer and exactly one custom deployment-branch policy named `main` before enabling
npm trusted publishing. A wildcard policy is not acceptable, and the generic
"protected branches" option is insufficient because it may admit protected release
branches. Enable prevention of self-review and disable administrator bypass as
defense-in-depth. The publish job queries the environment and its custom policies and
fails before package publication if the required controls are absent.

Configure npm's trusted publisher for this repository, the `publish-npm.yml` workflow,
and the `npm` environment. Do not add a long-lived npm token as a fallback. The workflow
passes only an inspected `.tgz` artifact to the privileged job, rejects any `scripts`
key in its package metadata, and invokes both `npm pack` and `npm publish` with
`--ignore-scripts`.

The release-action checker parses the workflow YAML structure rather than matching
source text, so quoted, flow-style, and explicit mapping keys cannot bypass it.
Repository-local actions and YAML aliases are prohibited in publishing workflows;
this keeps nested action dependencies from escaping the immutable-reference check.
Job containers and service images must also use immutable SHA-256 digests. The
`wasm-pack-action` installer and the `wasm-pack` binary version are pinned separately,
so a mutable tool download cannot change the package handed to the OIDC job.

## Baselines

Committed under [`.github/guardrails/`](../.github/guardrails/):

- `file-size-baseline.json` — ratchet for files already over the soft limit
- `ffi-kms.h.snapshot` — canonical C ABI header
- `wasm-exports.txt` — `wasm_bindgen` export surface

Shared extraction logic lives in [`.github/scripts/lib/surfaces.py`](../.github/scripts/lib/surfaces.py)
so checkers and regenerators cannot drift.

Regenerate after an intentional change:

```bash
bash .github/scripts/regenerate-guardrail-baselines.sh
```

Then add a short design note under `docs/design/` explaining why the surface grew.
Baseline / FFI / WASM snapshot updates require a real `docs/design/*.md` file (a PR-body
`## Design` heading alone is not enough).

## PR size scope (intentional)

`check-pr-size.sh` measures **production Rust sources** under `crates/**` (excluding
`experimental/`). Guardrail shell/Python is out of scope for that metric so policy
tooling can evolve without fighting its own line budget. Review still applies to those
scripts; they are covered by the fitness suite instead.

## Local pre-commit

```bash
git config core.hooksPath .githooks
```

Requires bash ≥ 4. The hook runs `cargo fmt` plus the fast fitness scripts.

The same checks are available without installing the hook:

```bash
bash tools/check.sh quick       # formatting + fast fitness checks
bash tools/check.sh guardrails  # fitness checks only
bash tools/check.sh all         # native Rust + fitness + WASM boundary
```

`.github/workflows/rust.yml` calls the granular `tools/check.sh` modes, keeping the
local agent/contributor path and the core Rust CI commands in sync.

## Design notes

Non-trivial public API, dependency, or boundary changes need:

- `docs/design/YYYY-MM-DD-slug.md`, or
- a `## Design` section in the PR description (except for security/boundary baseline
  updates, which require the file)

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

`controller` and `experimental/*` are also on the policy list so unknown crates fail
closed. `check-dependency-layers.sh` is the source of truth.

## Docs / missing docs trajectory

Publishable crates gate on **broken rustdoc links** today. Prefer documenting
every new `pub` item; a future ratchet may promote `missing_docs` crate-by-crate
once coverage is high enough.
