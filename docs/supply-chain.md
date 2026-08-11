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
