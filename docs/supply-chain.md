# Supply-chain notes

Records of provenance checks and pinning policy for dependencies that are not
plain crates.io semver deps. Update this file when re-verifying or when the
policy changes.

## `starknet-rust` crate family (production RPC/signer stack)

Verified 2026-08-10 against the crates.io API (audit finding M-19 in #46):

- **Publisher**: [Software Mansion](https://github.com/software-mansion) — the
  Starknet Foundry team. Crate owners are `Arcticae` (Tomasz Rejowski,
  Software Mansion) and the GitHub team `software-mansion:starknet-foundry`.
- **Repository**: <https://github.com/software-mansion/starknet-rust>
- This is the Software Mansion-maintained continuation of the `starknet-rs`
  stack, distinct from the upstream `starknet` crate. Provenance is considered
  verified; re-check owners when bumping major versions.

## Release path protections (GitHub)

- `crates-io` and `npm` are protected environments: required reviewers plus a
  custom deployment policy admitting exactly the `v*` **tag** pattern. Both
  release paths are tag-triggered. Both publish workflows read the environment
  through the read-only `GITHUB_TOKEN` and fail before minting a token if
  either control is missing. Configuration details and the exact
  checks are in [`crates-release.md`](crates-release.md#repository-protection).
- Two tag rulesets protect `v*` tags (created 2026-09-02): **creation** and
  **immutability** (update, deletion, non-fast-forward), both `active` on
  `refs/tags/v*` with the repository Admin role as the only bypass actor. The
  `crates-io` environment is configured (three required reviewers, prevent
  self-review on, administrator bypass on, one `v*` tag deployment policy) and
  passes the publish workflow's check. Details and payloads are in
  `crates-release.md`.
- Every `uses:` in every workflow is pinned to a commit SHA and checked by
  `.github/scripts/check-workflow-actions-pinned.sh`; release tooling
  (`wasm-pack`, `cargo-audit`, `cargo-deny`) is built from crates.io with
  `cargo install --version <exact> --locked`; and `cargo publish --locked`
  ships the dependency graph CI verified.

## Mapping a published npm package to its commit

`@starknetfoundation/krusty-kms-wasm` is the signing and derivation boundary for
released wallets, so "which source produced this tarball" has to be answerable by
anyone, not only by maintainers (issue #137).

Two records exist, and they are not equally trustworthy:

- **Signed provenance — authoritative.** `publish-npm.sh` publishes with
  `--provenance`, so npm stores a signed SLSA v1 attestation naming the
  repository, the workflow and the exact commit. It is signed through sigstore
  and cannot be edited afterwards. `npm audit signatures` verifies an installed
  copy; to read the commit directly:

  ```sh
  curl -s 'https://registry.npmjs.org/-/npm/v1/attestations/@starknetfoundation%2fkrusty-kms-wasm@0.11.0' \
    | jq -r '.attestations[] | select(.predicateType | test("slsa")) | .bundle.dsseEnvelope.payload' \
    | base64 -d \
    | jq -r '.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit'
  ```

- **`gitHead` in registry metadata — convenience only.** Recorded by the build
  job from `github.sha`, readable with
  `npm view @starknetfoundation/krusty-kms-wasm@<version> gitHead`. It is
  unsigned metadata, so it is a lookup aid; trust the attestation if the two ever
  disagree. wasm-pack builds into an out-dir with no git context, so npm cannot
  infer this by itself and the build job writes it explicitly. Versions 0.10.0
  and 0.11.0 were published before that step existed and record no `gitHead`;
  their commits are in the table below.

### Published versions and their commits

| npm version | Published | Commit (from provenance) | Tag | Tag commit |
| --- | --- | --- | --- | --- |
| 0.10.0 | 2026-08-28 | `2960c3af` | `v0.10.0` | `5ae1d986` — **does not match** |
| 0.11.0 | 2026-09-02 | `4dca96fc` | `v0.11.0` | `4dca96fc` — matches |

**The `v0.10.0` tag does not describe the published 0.10.0 package.** npm 0.10.0
was built from `2960c3af` on 2026-08-28. The tag was created later, on
2026-09-02, at `5ae1d986`, which additionally carries the Argent constructor
calldata fixes (#123, #131) folded in by #124. Anyone auditing npm 0.10.0 by
reading the `v0.10.0` tag would wrongly conclude those fixes shipped in it. They
did not. They are in npm 0.11.0, which is the current `latest`.

This happened because npm publishing used to trigger on pushes to `main`, so a
published version was not bound to a single commit the way the tag-triggered
crates.io release is. npm now publishes on `v*` tags too, and the workflow
refuses to publish unless the tag is reachable from `main` and matches the
version in the package being shipped. Both halves of a release therefore come
from one commit, and the tag and the artifact agree by construction.

The provenance attestation stays authoritative when the two records disagree,
because it is the signed one.

## Duplicate dependency versions (`cargo deny check bans`)

`deny.toml` sets `multiple-versions = "deny"`: a new duplicate crate version fails CI
unless it is listed under `[bans].skip` together with the transitive path that forces
it. Every current entry is a third-party stack that has not moved to the generation
krusty uses (RustCrypto 0.11, rand 0.10, syn 3). Reviewed 2026-09-02:

| Old generation | Forced by | Drops when |
| --- | --- | --- |
| aes 0.8, cipher 0.4, crypto-common 0.1, inout 0.1, ctr 0.9, scrypt 0.10, salsa20 0.10, pbkdf2 0.11, thiserror 1 | `starknet-rust-signers 0.19.1 → eth-keystore 0.5.0` (Ethereum keystore loading; krusty never calls it) | starknet-rust bumps eth-keystore |
| hmac 0.12, sha2 0.10, digest 0.10, block-buffer 0.10, cpufeatures 0.2, rfc6979 0.4 | `starknet-rust-crypto 0.19.1` (also eth-keystore, lambdaworks-crypto, ed25519-dalek) | starknet-rust-crypto moves to RustCrypto 0.11 |
| num-bigint 0.4, sha3 0.10, keccak 0.1, rand 0.8, rand_core 0.6 | `starknet-types-core 0.2.4 → lambdaworks-math / lambdaworks-crypto 0.13` (also starknet-rust-core, eth-keystore, nkeys) | lambdaworks and starknet-rust move to num-bigint 0.5 / rand 0.10 |
| pkcs8 0.10, spki 0.7, der 0.7, const-oid 0.9, signature 2 | `async-nats 0.50 → nkeys 0.4 → signatory 0.27 / ed25519-dalek 2` (only behind `krusty-kms-client/nats`) | nkeys moves to pkcs8 0.11 / signature 3 |
| getrandom 0.2 | `krusty-kms-wasm` / `mental-poker-wasm` add it with the `js` feature so rand_core 0.6 consumers work in browsers; ring 0.17 and uuid 0.8 also use it | no rand_core 0.6 consumer is left in the wasm graph |
| syn 2 | every proc-macro crate except async-trait 0.1.92 (already on syn 3) | the proc-macro ecosystem finishes the syn 3 transition |

The lockfile also lists rand 0.9, rand_core 0.9, and getrandom 0.3. They are reached
only through `proptest` as a dev-dependency of the experimental `mental-poker` crate,
so `cargo deny check bans` does not report them and no skip is needed; if a production
crate ever pulls them in, the gate fails and a justified skip (or an upgrade) is required.

When a skip stops matching anything, `cargo deny` warns; delete the entry rather than
leaving a stale allowance. Prefer `skip` over `skip-tree`: a subtree skip would also
accept duplicates introduced later underneath it.

Resolved 2026-09-02: `krusty-kms` now signs with `starknet-rust-crypto` 0.19.1 (the
version the `starknet-rust` 0.19.1 stack already links) instead of a second 0.9.0
copy, which removed `starknet-rust-crypto` 0.9.0, `starknet-rust-curve` 0.6.0 and
`crypto-bigint` 0.5.5 from the lockfile.

## `account_sdk` (Cartridge Controller, git-only)

- Used only by `crates/controller`, which is **workspace-excluded** and
  `publish = false`. It must not be wired into production builds without a
  security review of its dependency stack.
- Pinned by **commit rev** (not tag) in `crates/controller/Cargo.toml`: git
  tags are mutable, so a tag pin could be silently repointed upstream.
- Its cargo-audit ignores live in `crates/controller/.cargo/audit.toml`,
  scoped to that crate. The workspace-root `.cargo/audit.toml` ignore list is
  intentionally empty — keep it that way unless an advisory affects the root
  `Cargo.lock` and genuinely cannot be fixed.
- The crate is its own workspace root (`[workspace]` in its manifest), so it
  resolves into `crates/controller/Cargo.lock`, never into the production
  lockfile. Audit it from its own directory so cargo-audit reads that file:

  ```bash
  cd crates/controller
  cargo generate-lockfile   # network: fetches the pinned account_sdk rev
  cargo audit --deny warnings
  cargo test --locked --features sdk
  ```

- **Status 2026-09-02 (audit finding M-9): the crate does not resolve.**
  `account_sdk` at the pinned rev `4ec2e4fc` (tag v0.10.1, which is also the
  tip of upstream `main`) requires `starknet-types-core = "=0.2.0"`, while
  `krusty-kms-common` has required `^0.2.4` since the 0.6.0 workspace bump.
  Cargo resolves optional dependencies into the lockfile, so even the default
  feature set fails to generate `Cargo.lock`; no lockfile, audit, or CI job can
  exist until one of these happens:
  - upstream `cartridge-gg/controller-rs` relaxes the `starknet-types-core`
    pin — re-verify the new rev's owners and dependency stack before bumping
    `rev`, and record the tag it corresponds to; or
  - the adapter stops depending on the `krusty-kms-common` /
    `krusty-kms-wallet-api` path crates and carries the small `Address`,
    `ChainId`, and `Tx` surface it uses.

  Until then the ignore list in `crates/controller/.cargo/audit.toml` cannot be
  re-verified and should be treated as stale.
