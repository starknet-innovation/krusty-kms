# Keep CI guardrails current with Rust 1.100

Rust 1.100 reports redundant boolean branches in the audit and bit proof
verifiers and an indexed loop in the experimental shuffle implementation.
Return the existing verification result directly and iterate over the same
permutation entries. These changes preserve verification behavior and the
public API.

Regenerate the file-size and function-size baselines after those cleanups.
Every changed limit decreases: audit.rs 828 to 824 lines, bit.rs 360 to 356,
shuffle.rs 686 to 685, and the audit verifier 118 to 114. No guardrail is
relaxed, and neither the FFI nor WASM surface changes.

Rust 1.100 coverage also exposed an existing gap in the RPC account-state
adapter tests. Exercise truncated responses and each invalid curve point,
asserting deserialization errors. Keep the 38% adapter coverage floor;
the added rejection cases raise measured adapter coverage to 44.87%.

Validation uses the canonical tools/check.sh modes, the scoped coverage
checker, and regeneration followed by a clean baseline diff.
