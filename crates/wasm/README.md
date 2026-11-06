# @starknetfoundation/krusty-kms-wasm

Browser-focused WebAssembly bindings for Krusty KMS account, signing, hashing,
and Starknet utilities.

## Install

```sh
npm install @starknetfoundation/krusty-kms-wasm
```

## Use

Initialize the module before calling its exports:

```ts
import init, {
  getVersion,
  poseidonHash,
} from "@starknetfoundation/krusty-kms-wasm";

await init();

console.log(getVersion());
console.log(poseidonHash("0x1", "0x2"));
```

## Felt inputs

Felt arguments accept decimal digit strings (`"1000"` means one thousand) or
`0x`/`0X`-prefixed hexadecimal strings (`"0x1000"` means 4096). This applies
to felt values in `compileCalls`, transaction hashes, account addresses,
signing, hashing, point coordinates, and proof inputs. Unprefixed hexadecimal
text such as `"abcd"`, whitespace, and values outside the Stark field are
rejected. `encodeFelt` also accepts booleans and surrounding whitespace.
Byte strings and Nostr identifiers have their own documented formats.

**Behavior change:** Earlier versions silently read unprefixed digit strings
as hexadecimal in most exports. Callers that intended hexadecimal must add
`0x`; callers that intended decimal can keep their digit strings.

Run `init()` once and share its promise. Once `init()` has resolved, calling
it again returns the same instance, but two calls that overlap (the second
starting while the first is still loading) each instantiate the module. The
one that finishes last replaces the instance under every object created on
the other: their getters fail with `RuntimeError: Out of bounds memory
access`, and their frees can release objects the new instance has since
created.

```ts
// krusty.ts: the one place that initializes the module
import init from "@starknetfoundation/krusty-kms-wasm";

export const krustyReady = init();
```

## Secrets

Exports that take a secret (mnemonic, passphrase, password, private key,
seed, symmetric key, plaintext) wipe their WASM copy of it when the call
returns. They cannot wipe your JavaScript string, and a non-ASCII string can
leave a partial copy in freed WASM memory. Secrets an export returns (derived
or decrypted keys, mnemonics, plaintexts, viewing keys) are plain JavaScript
strings: keep them out of logs and persistent storage.

This package is generated with `wasm-pack --target web` and is intended for
browser-oriented ESM toolchains that support loading WebAssembly modules.

Krusty KMS is experimental. Do not rely on it for production or
security-critical use.

## License

MIT OR Apache-2.0
