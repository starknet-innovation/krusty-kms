# Preserve nullable optional WASM TypeScript inputs

The exact-integer change in #240 moved several optional WASM parameters from
`Option<T>` to `JsValue`. The numeric parser still treats `null` and
`undefined` as absent, but the generated TypeScript declarations lost `null`.
Strict TypeScript callers that passed an explicit `null` could no longer
compile, although the same call still worked at runtime.

Annotate the seven discovery indices, mnemonic word count, balance search
limit, and two proof bit-size setters with their existing nullable TypeScript
types. Keep `JsValue` and the exact-integer parser, so there is no runtime
conversion or security-policy change. Restore documentation on the proof-width
accessors and update the WASM export snapshot for these intentional type
declarations.

Validation builds the pre-#240 and fixed packages and compares the eleven
affected `.d.ts` signatures. They match exactly. The canonical quick and WASM
checks also pass. This follow-up does not publish the npm package; it will be
included in a later workspace-version release.
