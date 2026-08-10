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
- **Gotcha:** exclude the WASM crate from normal cargo runs — it only builds/tests under
  `wasm-pack`. CI uses `cargo test --workspace --exclude krusty-kms-wasm`. Running plain
  `cargo test --workspace` will try to native-compile `krusty-kms-wasm`.
- Run the WASM boundary tests separately with `wasm-pack test --node crates/wasm`.
- Examples double as the "hello world" smoke test, e.g.
  `cargo run -p krusty-kms --example key_derivation` (also `stark_sign`, `oz_address`,
  and `cargo run -p krusty-kms-sdk --example tongo_proof_generation`).

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
