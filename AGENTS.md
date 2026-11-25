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

### Pull requests (mandatory independent review)

Any agent opening a pull request in this repository, as a draft or ready for review,
must first have the change fully reviewed by an independent review agent and must
address every finding before the PR is opened. The same gate applies before marking a
draft ready for review.

- **Independent:** the reviewer is a separate agent or subagent. It may be the same
  model, but it starts from a fresh context and does not inherit the author's
  conversation, reasoning or conclusions. Give it the full diff against the PR's base
  branch (normally `origin/main`), the PR's purpose, and the files it needs to read,
  then let it form its own view. Automated reviewers that run after the PR is open
  (for example Greptile) do not satisfy this requirement.
- **Full review:** the whole diff, not a sample. Cover correctness, security
  (key material, secret hygiene, input validation, `unsafe`), public API and semver
  impact, FFI/WASM boundary changes, tests, and fit with
  [`CONTRIBUTING.md` "Review standards"](CONTRIBUTING.md#review-standards) and
  [`docs/maintainability-guardrails.md`](docs/maintainability-guardrails.md).
- **Address findings first:** fix each finding, or explain why it is a false positive
  or out of scope. Do not open the PR while a finding is unresolved.
  - Any fix other than a typo, formatting or broken-link correction requires a
    re-review of the updated diff. This includes changes to rules in `AGENTS.md`,
    `CONTRIBUTING.md`, `SECURITY.md` or `docs/`. Rerun the appropriate
    `tools/check.sh` mode after the fixes.
  - A high- or medium-severity finding may be dismissed only if the re-review accepts
    the reasoning or a human maintainer does. Otherwise stop and ask a human.
- **Record it:** add an "Independent review" section to the PR description (for
  release PRs, under Verification) saying that the review ran, what it found, and how
  each finding was resolved. If a finding is a security vulnerability that the PR does
  not fully fix, do not describe it in the PR: hand it to a human maintainer to report
  privately as `SECURITY.md` describes, and note only that a finding was reported
  privately. Keep a fixed but unreleased vulnerability out of public PR wording until
  disclosure is coordinated: describe such a finding neutrally (for example
  "hardening fix") in the PR description and in review comments alike.
- **Later pushes:** commits pushed to an open PR (for example fixes for human or bot
  review comments) need an independent review of the new delta before pushing, with
  its findings addressed as above and recorded in a PR comment, unless they would be
  exempt from re-review under the rule above.
- **No reviewer available:** if the environment cannot start an independent reviewer,
  do not open the PR, mark a draft ready, or push reviewable commits to an open PR.
  Push to a separate branch if needed, report that review is pending, and hand off to
  a human.
- This applies to every PR an agent opens, including release PRs, docs-only changes
  and follow-up fixes. It adds to human review and CI; it does not replace them.

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
   succeeded. Read `## [Unreleased]` and `git log v<last>..origin/main`. The crates are
   4.x and follow semver: a patch bump when every bullet is `Fixed` or `Security`; a
   minor bump when any bullet is `Added`, `Deprecated` or a non-breaking `Changed`; a
   major bump only for a **Breaking** bullet or any `Removed` entry (removing public
   API is breaking). Pick the bump from `## [Unreleased]`.
   `cargo-semver-checks` (`.github/scripts/check-semver.sh`) checks feature PRs against
   the base branch with `--release-type minor`, so only breaking changes fail them. On
   the release PR it compares against the previous tag `v<base version>` with no
   override, so it rejects a bump too small for the API changes it detects (a patch
   over pending additions fails with "requires new minor version"; a missing tag fails
   closed). It does not lint a changed return type on an inherent method or free
   function: treat that as **Breaking** by hand. A deterministic key/address change
   for valid inputs is also **Breaking**, even if signatures stay the same; document
   recovery/migration for accounts created with the previous derivation.
   A breaking change is not merged past a
   red semver check within a major; it waits for the next major plan, and lands in
   that major's release PR, because only a version-bumping PR is checked at its
   actual increment. If `## [Unreleased]` is empty, there is
   nothing to release.
2. **Branch and bump.** On a focused release branch, change the root
   `[workspace.package].version`. Internal `krusty-kms-*` path dependency requirements
   in `crates/*/Cargo.toml` (currently `4.0.0`) need no move for compatibility on patch
   and minor bumps, because `^4.0.0` covers every 4.x. Raise a requirement's lower
   bound when the dependent crate starts using an API or relying on behavior added
   in a later 4.x of that dependency (including security invariants); otherwise a lockfile still on the older version satisfies the range and
   fails to compile. Move every
   requirement to the new major on a major bump.
3. **Changelog.** Rename the pending notes into `## [<version>] - YYYY-MM-DD` and keep
   an empty `## [Unreleased]` above it. Run `.github/scripts/verify-release-changelog.sh`.
4. **Design note.** Add `docs/design/<date>-release-<version>.md`, following the
   earlier ones: what is included, why this increment, and whether internal dependency
   ranges moved.
5. **Verify.** Run `cargo check --workspace --all-targets` to refresh `Cargo.lock`, then
   the playbook's `cargo package --locked` preflight and `bash tools/check.sh all`.
6. **Open the PR** after the independent review (see Pull requests above), titled
   `chore(release): prepare Krusty <version>`, with Summary, Design, Verification and
   Publication sections. Merging it is the maintainer's call.
7. **Tag after merge.** A maintainer tags the merged `main` commit as `v<version>` and
   pushes it. The tag rulesets let only the repository Admin role create `v*` tags. The
   `crates-io` environment then waits for reviewer approval or an admin bypass. After the
   crates publish, the workflow creates the GitHub Release from the version's changelog
   section; do not create it by hand.

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
