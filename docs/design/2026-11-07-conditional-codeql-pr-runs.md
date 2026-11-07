# Run CodeQL on pull requests only for the languages they touch

Date: 2026-11-07. Status: proposed.

CodeQL ran through GitHub's default setup, which analyzes all five languages
(actions, c-cpp, javascript-typescript, rust, swift) on every pull request.
Default setup has no path filters. A docs-only PR still paid for the full set,
including the Swift job: an autobuild on a macOS runner that took about 16
minutes of the ~16-minute wall clock (rust ~6 min, the rest under a minute).

`.github/workflows/codeql.yml` moves CodeQL to advanced setup with the same
configuration as default setup: the same languages, the `security-extended`
suite, `build-mode: none` everywhere except Swift (`autobuild` on `macos-26`),
and one `/language:<lang>` category per language. It also adds
`java-kotlin`, which default setup did not analyze although
`packages/kms-jvm` holds Java and Kotlin sources; Kotlin has no
`build-mode: none`, so that job builds manually with the same
`gradle classes` step as `wrappers.yml`.

Known gap: `packages/kms-jvm` builds with Kotlin 2.4.21, while the pinned
CodeQL bundle (2.27.4, action v4.39.3) documents Kotlin support up to 2.4.20.
The job passes and the Java sources are analyzed, but the Kotlin source
(`KmsKt.kt`, a thin wrapper) may not be extracted. We accept this until a
CodeQL bundle supports 2.4.21 rather than pin the product build to an older
Kotlin; Dependabot's github-actions updates will bring that bundle in. A `changes` job lists the
PR's files through the REST API and `.github/scripts/codeql-languages.sh` maps
them to languages; the analyze matrix covers only those. A PR that touches no
analyzed language skips the analyze job entirely.

Kept full:

- pushes to `main` and a weekly schedule analyze every language, so the base
  results that PR alerts are compared against stay current for all languages;
- a change to the CodeQL workflow or the mapping script selects every language;
- if the file listing fails, the job falls back to every language rather than
  none.

Trade-off: the mapping is by file extension and package directory. Swift is
analyzed only when Swift sources or `packages/kms-swift/` change, not when the
Rust core behind the Swift bindings changes; CodeQL's Swift analysis only
covers Swift source, so the Rust change is covered by the rust job.

No ruleset requires a CodeQL check, so skipped languages do not block merges.

Rollout: default setup must be disabled in Settings > Code security before
the workflow can upload results; while both are on, uploads from the workflow
are rejected.
