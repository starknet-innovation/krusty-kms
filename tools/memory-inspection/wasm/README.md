# Optimized WASM memory inspection

This standalone, unpublished adapter is outside the production workspace.
The common inspection runner supplies a clean source snapshot and a control
snapshot in which exactly the `scrub_stack();` call is disabled. This backend
builds one supplied variant:

```sh
python3 tools/memory-inspection/wasm/run.py \
  --source-root /path/to/snapshot --mode clean \
  --report /tmp/wasm-clean.json --toolchain 1.100.0
```

Use `--mode control` for the validated disabled-scrub snapshot. Both modes
must succeed; the control is inconclusive and exits nonzero unless **every**
operation/fixture exposes at least one searched secret pattern outside
the exact input/output ranges. The probe has its own committed lockfile and builds with `--locked`,
`opt-level=3`, one codegen unit and no LTO. Install the wasm32 target and
`wasm-bindgen` CLI 0.2.127 (the version pinned by its lockfile). Node 22 is
used locally. Reports identify the actual compiler, Node and optimization.

## Observation boundary

Node creates fresh synthetic entropy at runtime for 12- and 24-word English
phrases, plus an ASCII passphrase. A disposable preparation instance obtains
the canonical phrase. Each operation then uses a **fresh target instance**,
so preparation cannot contaminate the scanned memory. The generation case
uses the production `wasm_js` entropy backend, with a test-only Node
`globalThis.crypto.getRandomValues` provider filling the requested destination.
There is no production feature, entropy hook, or fixture in WASM data segments.

Node scans the entire linear memory, including freed heap and dead stack,
immediately after the target export returns. No WASM getter, allocator, or
other call occurs between the operation and scan. The scanner searches exact
entropy bytes, expanded bits, little-endian word indices, phrase, passphrase,
SHA-512 of the phrase, seed, and 128-byte HMAC pads. Only match counts and
excluded buffer kinds/lengths are reported; fixture values and memory dumps
are never printed or saved.

The only exclusions are exact ranges for host-supplied input, a returned
phrase's UTF-8 allocation, or the **64-byte caller return slot** containing
the returned seed. The adapter records that seed pointer from its live
`Result` and forgets the result; the immediate host scan cannot reuse this
slot. The slot is caller material explicitly outside the library's wiping
claim. No entire frame or stack region is excluded, and any additional seed
copy fails the clean scan. An initial adapter that transferred the seed into
`Option<Zeroizing<_>>` itself left two extra caller-frame copies; registering
the original return slot avoids those transfers instead of masking them.

## Limits

This is a reproducible check for the searched representations on the recorded
compiler/optimization, not proof of absence of all secrets. It exercises
`mnemonic_from_entropy`, `validate_mnemonic`, `mnemonic_to_seed`, and
`generate_mnemonic`; it covers English ASCII phrases and ASCII passphrases.
It does not cover documented non-ASCII NFKD heap copies, long combining-mark
buffers, registers, other compiler-generated encodings, other targets, or
arbitrarily deep dependency frames. Dependency changes require rerunning
both variants. Each control must actually detect remnants so a broken or
insensitive scanner cannot silently pass.

On Rust 1.100 locally, the disabled-scrub seed cases exposed one additional
64-byte seed outside the registered caller slot; they did not expose the
searched entropy, index or HMAC representations. Those cases calibrate
seed-copy detection specifically. The other disabled-scrub operations
exposed entropy bytes, entropy bits and word indices. All searched counts
were zero in the clean build. Exact locations and representations remain
compiler-dependent; the report records counts separately.
