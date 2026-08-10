# AGENTS.md

## Cursor Cloud specific instructions

Krusty (`krusty-kms`) is a Rust workspace of cryptography / Starknet key-management
crates. It is a **library/SDK**, not a long-running service — there is no web server,
database, or daemon to start. "Running the app" means running the crate examples and
the test suites. Standard commands live in `README.md`, `crates/CLAUDE.md`, and
`.github/workflows/rust.yml`; prefer those over duplicating here.

### Toolchain notes (non-obvious)

- The workspace MSRV is **1.92** (`Cargo.toml` `[workspace.package] rust-version`).
  A Rust **stable** toolchain (>= 1.92) is installed and set as the rustup default in
  this environment; the base image's older `rustc` is not sufficient. If `rustc
  --version` ever reports < 1.92, run `rustup default stable`.
- `wasm-pack` and the `wasm32-unknown-unknown` target are installed for the WASM crate.
- Node 22 is available for the optional TypeScript cross-compatibility tests.

### Build / lint / test

- Build/lint/test the Rust workspace with the commands in `README.md` and
  `.github/workflows/rust.yml`.
- Maintainability fitness checks (file-size ratchet, dependency DAG, `unsafe`
  allowlist, secret hygiene, FFI/WASM freezes, `cargo-deny`, rustdoc links,
  semver-checks) live in `.github/workflows/guardrails.yml` and are documented in
  [`docs/maintainability-guardrails.md`](docs/maintainability-guardrails.md).
- **Gotcha:** exclude the WASM crate from normal cargo runs — it only builds/tests under
  `wasm-pack`. CI uses `cargo test --workspace --exclude krusty-kms-wasm`. Running plain
  `cargo test --workspace` will try to native-compile `krusty-kms-wasm`.
- Run the WASM boundary tests separately with `wasm-pack test --node crates/wasm`.
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
