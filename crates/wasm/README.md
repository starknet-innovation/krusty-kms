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

This package is generated with `wasm-pack --target web` and is intended for
browser-oriented ESM toolchains that support loading WebAssembly modules.

Krusty KMS is experimental. Do not rely on it for production or
security-critical use.

## License

MIT OR Apache-2.0
