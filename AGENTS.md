# AGENTS.md

## Cursor Cloud specific instructions

Krusty (`krusty-kms`) is a Rust workspace of cryptography / Starknet key-management
crates. It is a **library/SDK**, not a long-running service — there is no web server,
database, or daemon to start. "Running the app" means running the crate examples and
the test suites. `tools/check.sh` is the canonical command surface used by both local
work and `.github/workflows/rust.yml`; do not duplicate its cargo command sequences.

### Start here

- Run `bash tools/check.sh quick` before editing to catch existing local drift.
- Read the affected crate's `Cargo.toml` and `src/lib.rs` before changing internals;
  those files define its dependencies, safety policy, and public boundary.
- Use `bash tools/check.sh rust` for native Rust changes, add
  `bash tools/check.sh wasm` for WASM changes, and run `bash tools/check.sh all`
  before handing off a cross-cutting change.
- Keep validation proportional while iterating: a focused `cargo test -p <crate>
  <test-name>` is preferred, followed by the appropriate canonical check mode.
- `CONTRIBUTING.md` owns design policy and the current crate map;
  `docs/maintainability-guardrails.md` explains CI-enforced boundaries.

### Toolchain notes (non-obvious)

- The workspace MSRV is **1.92** (`Cargo.toml` `[workspace.package] rust-version`).
  A Rust **stable** toolchain (>= 1.92) is installed and set as the rustup default in
  this environment; the base image's older `rustc` is not sufficient. If `rustc
  --version` ever reports < 1.92, run `rustup default stable`.
- `wasm-pack` and the `wasm32-unknown-unknown` target are installed for the WASM crate.
- Node 22 is available for the optional TypeScript cross-compatibility tests.

### Build / lint / test

- Build/lint/test the Rust workspace through `tools/check.sh`; CI calls the same modes.
- Maintainability fitness checks (file-size ratchet, dependency DAG, `unsafe`
  allowlist, secret hygiene, FFI/WASM freezes, `cargo-deny`, rustdoc links,
  semver-checks) live in `.github/workflows/guardrails.yml` and are documented in
  [`docs/maintainability-guardrails.md`](docs/maintainability-guardrails.md).
- **Gotcha:** exclude the WASM crate from native cargo tests. `tools/check.sh test`
  does this automatically; `tools/check.sh wasm` runs the boundary tests separately.
- Examples double as the "hello world" smoke test, e.g.
  `cargo run -p krusty-kms --example key_derivation` (also `stark_sign`, `oz_address`,
  and `cargo run -p krusty-kms-sdk --example tongo_proof_generation`).
- Optional `--ignored` suites are exercised by
  `.github/workflows/ignored-integration.yml` (weekly compile + manual dispatch).

### crates.io releases (maintainers and agents)

Read [`docs/crates-release.md`](docs/crates-release.md) before preparing or operating
a crates.io release. The workflow in `.github/workflows/publish.yml` is the source of
truth.

- Never run `cargo publish` locally and never add or request a long-lived crates.io
  token. Publishing uses GitHub Actions OIDC and the protected `crates-io` environment.
- Bump the root `[workspace.package].version`, update `Cargo.lock`, create a dated
  `CHANGELOG.md` entry with a release-note bullet, and complete the package preflight
  before opening the release PR. CI rejects a version bump without that entry.
- Only tag the merged `main` commit as `v<workspace-version>`; pushing that immutable
  tag starts the release. Do not move, recreate, or force-push a release tag.
- A transient or partial release is recovered by rerunning the existing workflow run.
  The publish script skips crates that already exist. If code must change, prepare a
  new patch version and tag instead.

Release steps (commands are in the playbook; do not copy them here):

1. **Pick the version.** Start from current `main`. Confirm its workspace version is the
   latest published `krusty-kms` on crates.io and that the last `publish.yml` run
   succeeded. Read `## [Unreleased]` and `git log v<last>..origin/main`. Use a patch
   bump for fixes and a minor bump for behavior or API changes (the crates are pre-1.0).
   If `## [Unreleased]` is empty, there is nothing to release.
2. **Branch and bump.** On a focused release branch, change only the root
   `[workspace.package].version`. For a minor bump, also move every internal
   `krusty-kms-*` path dependency requirement in `crates/*/Cargo.toml` to the new
   version, because pre-1.0 caret ranges exclude the next minor. A patch bump leaves
   them alone.
3. **Changelog.** Rename the pending notes into `## [<version>] - YYYY-MM-DD` and keep
   an empty `## [Unreleased]` above it. Run `.github/scripts/verify-release-changelog.sh`.
4. **Design note.** Add `docs/design/<date>-release-<version>.md`, following the
   earlier ones: what is included, why this increment, and whether internal dependency
   ranges moved.
5. **Verify.** Run `cargo check --workspace --all-targets` to refresh `Cargo.lock`, then
   the playbook's `cargo package --locked` preflight and `bash tools/check.sh all`.
6. **Open the PR** titled `chore(release): prepare Krusty <version>`, with Summary,
   Design, Verification and Publication sections. Merging it is the maintainer's call.
7. **Tag after merge.** A maintainer tags the merged `main` commit as `v<version>` and
   pushes it. The tag rulesets let only the repository Admin role create `v*` tags. The
   `crates-io` environment then waits for reviewer approval or an admin bypass.

The WASM npm package (`@starknetfoundation/krusty-kms-wasm`) takes the workspace
version. `publish-npm.yml` runs on merge to `main` and skips versions already on npm.
Merging a version bump therefore starts an npm publish with no tag involved, gated
only by the protected `npm` environment's reviewer approval. WASM-only fixes reach
npm only through a workspace version bump.

### Optional integration tests (external services required)

Some tests are gated behind `-- --ignored` and are **not** part of the default suite.
They need external tooling that is **not** preinstalled here:

- `starknet-devnet` (local devnet on `127.0.0.1:5050`) for on-chain multisig tests.
- `scarb` + Starknet Foundry `sncast` to build/declare the Cairo contracts in
  `contracts/`.
- a `nats-server` (or Docker) for the multisig coordinator pub/sub tests.
- internet access to a live Starknet Sepolia RPC for the live Tongo integration test.

Install these on demand only if you need to exercise those `--ignored` flows.

### Cross-compat (TypeScript) tests — optional

The `cross-tests/` harness re-verifies Rust-generated vectors with `starknet.js` /
`@fatsolutions/tongo-sdk`. Run `npm ci` in `cross-tests/` first (it is not part of the
startup update script); see `.github/workflows/cross-compat.yml` for the exact flow.
