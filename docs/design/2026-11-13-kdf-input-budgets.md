# Password KDF input budgets

## Context

The direct private-key API previously accepted scrypt `N=2^20`, which asks for
about 1 GiB of ROMix memory with its fixed `r=8`. The keystore import path had
a 256 MiB ceiling, but parsed unrestricted JSON and decoded salt text before
checking its length. A v3 keystore could also request excessive total work by
combining a high `p` with a modest memory footprint.

## Design

New direct encryption and the default WASM decryption export now use a 256 MiB
KDF memory budget. Existing native `decrypt_private_key` keeps the old range
because ciphertext previously created with high N must remain recoverable;
native applications handling untrusted metadata can use
`decrypt_private_key_bounded`. WASM applications use `decryptPrivateKeyHighCost`
only for deliberate recovery of older ciphertext. No KDF parameter is silently
downgraded. The encrypted-key wire format is unchanged.

The Rust caller owns the `EncryptedKey` values and the choice to invoke the
legacy high-cost function. Passing untrusted metadata to that legacy function
can still request up to about 1 GiB of scrypt scratch; use the bounded API at
that boundary. Both Rust decryption paths reject ciphertext outside the AEAD
tag and 1 MiB limits, invalid nonce length, and direct salt lengths other than
16 bytes before KDF work.

Both keystore imports reject JSON over 1 MiB before `serde_json` allocates its
tree. Salt text is length-checked before hex decoding, and v3 `N*r*p` is capped
to the work of the usual 256 MiB, `r=8`, `p=1` parameter set. The direct KDF
rejects salts over 128 bytes. WASM direct decryption also checks encoded salt
and ciphertext lengths before decoding, including the fixed-size nonce. All
WASM scrypt-N exports validate the exact JavaScript number before conversion,
so a value such as `2^32 + 1024` cannot wrap to the accepted `1024`. Their
generated TypeScript declarations retain the `number` parameter type.

Direct private-key encryption checks the hex input length before starting the
KDF, and caps plaintext at 1 MiB minus the AEAD tag so WASM can decrypt every
newly created direct key ciphertext.

Native keystore encryption rejects mnemonic text over 4096 bytes before KDF
work, keeping every newly written file below the import ceiling.

## Compatibility and verification

Only newly encrypted keys are forced to the default 256 MiB budget. The
existing Rust decryption function and the named WASM high-cost recovery export
retain the old N range. The WASM export snapshot records the one added name.
The default WASM decryption export reports an over-budget legacy N as a
serialization error and names `decryptPrivateKeyHighCost`, so it is distinct
from a wrong-password crypto error. Owned WASM passwords are wrapped in
`Zeroizing` before numeric validation, including on this failure path.
Malformed scrypt-N values also return a structured serialization error;
`WasmError` now includes its existing code in the JavaScript Error object.
`CHANGELOG.md` records the tighter direct salt, plaintext, v3 work, and exact
JavaScript-number contracts for existing public entry points.
Tests use small fixtures to assert rejection before KDF work, verify ordinary
roundtrips and the explicit recovery entry point, and run the canonical Rust
and WASM checks. No 512 MiB or 1 GiB allocation is needed to test the limits.
