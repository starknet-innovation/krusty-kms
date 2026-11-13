# Exact integer inputs at the WASM boundary

JavaScript `number` arguments to `wasm-bindgen` exports were previously
narrowed to Rust integers before the export body could validate them. A value
such as `2^32` could become derivation index zero, and `256` could become DA
mode zero or a proof bit size of zero. The invariant is that the integer used
for key derivation, signing context, proof generation, discovery, or bounded work
must equal the integer supplied by the caller.

The exports now receive raw `JsValue`s and parse them into bounded integers
before use. Invalid, fractional, negative, non-finite, and out-of-range values
return a JavaScript error. Optional indices still default when omitted. The
account nonce and optional balance search bound remain `bigint`s in the
generated TypeScript API; bounded `number` parameters retain their existing
TypeScript type. Valid values and
export names are unchanged.

The Rust signatures of this npm-only crate change to implement the JavaScript
boundary check. Tests cover the parser and representative exports, including
wrapped indices, nonce overflow, proof bit size, and direct setters. Scrypt
work-factor validation is handled in the separate KDF remediation. The
WASM export snapshot and generated TypeScript declarations are checked before
handoff.

The change spans multiple export modules because each public numeric argument
and generated setter needs to receive the original JavaScript value before
narrowing. Existing tests and conversion helpers were moved into modules to
keep source files within the repository's file-size guardrail; those moves
account for much of the diff without changing their behavior.
