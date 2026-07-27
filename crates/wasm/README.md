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

This package is generated with `wasm-pack --target web` and is intended for
browser-oriented ESM toolchains that support loading WebAssembly modules.

Krusty KMS is experimental. Do not rely on it for production or
security-critical use.

## License

MIT OR Apache-2.0
