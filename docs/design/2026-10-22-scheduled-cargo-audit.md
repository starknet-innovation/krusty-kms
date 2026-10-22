# Scheduled advisory sweep of the main lockfile

The `security` job in `rust.yml` runs `cargo audit --deny warnings` against the
root `Cargo.lock`, and the `deny` job in `guardrails.yml` runs `cargo deny check`
for yanked crates and unmaintained advisories. Both ran only on `push` and
`pull_request`, so a new RUSTSEC advisory produced no signal until some PR
happened to touch a path in the workflow filters. Three advisories published on
19–20 October 2026 sat on `main` unnoticed until Dependabot PRs ran CI and went
red; the lockfile fix is a separate PR.

Both workflows now also run on a weekly `schedule` (Mondays 06:30 UTC, after the
06:15 ignored-integration bitrot run), which GitHub executes against the default
branch. On that event only the advisory jobs run: `check`, `msrv`, `package`,
`wasm`, `fitness`, `docs`, and `semver` carry `if: github.event_name != 'schedule'`,
and `version-bump` was already limited to pull requests. `fitness` and `semver`
also depend on a base revision that a scheduled run does not have, so gating them
is required, not just an economy.

The scheduled run covers the same thing as the PR run: the root lockfile with the
empty ignore list in `.cargo/audit.toml` and the `[advisories]` policy in
`deny.toml`. The `krusty-kms-controller` crate is workspace-excluded and audited
from its own lockfile; it is not covered here. A failing scheduled run shows up on
the Actions tab for `main` and in the workflow's failure notifications; it does
not open an issue or block anything on its own.

`permissions` stays `contents: read` in both workflows, and no new `${{ }}`
interpolation reaches a `run:` step. Action references are unchanged and remain
SHA-pinned. A scheduled run has no `github.base_ref`, so the gated jobs are the
ones that would have read it.
