# Wipe secret string inputs at the WASM boundary

Date: 2026-11-03. Status: proposed. Stacked on
`2026-11-03-zeroize-shared-derivation.md`, whose inventory lists this item.

## Problem

For a `&str` argument, wasm-bindgen's JS glue (`passStringToWasm0`) mallocs
a buffer in WASM memory and writes the string's UTF-8 into it. The Rust shim
wraps the buffer in a `Box<str>`, lends it to the export, and frees it when
the call returns, without wiping it. The bytes stay in linear memory until the
allocator reuses them. For an owned `String`, the glue is the same, but the
shim builds a `String` from that buffer and moves it into the export, which
can wipe it.

39 exports took a mnemonic, private key, password, seed, symmetric key,
plaintext, scalar, or viewing-key signature as `&str`. Several also made
unwiped copies while parsing:

- `hex::decode` collects into a `Vec` that grows by reallocation, so each
  outgrown buffer holding part of the decoded Nostr key, symmetric key, or
  grinding seed was freed unwiped, then the `Vec` itself.
- The STRK20 non-reduction check formatted the private key, or `r`/`s`, into
  two `String`s (`to_ascii_lowercase`, then `format!`) and the parsed felt into
  a third.
- Parsed private keys sat in plain `Felt`s and `[u8; 32]`s.
- `WasmAccount.fromMnemonic` parsed the contract address before wrapping the
  passphrase, so a refused address freed the passphrase unwiped.
- `decryptWithKey` dropped a decrypted plaintext that was not UTF-8 unwiped.

## Change

- Each of the 39 exports takes its secret arguments as `String`, and its first
  statement puts them in `Zeroizing`. The buffer is wiped when the call
  returns, whether it succeeds or fails.
- A crate-private `secret_input` module parses secrets without copying them to
  the heap:
  - `decode_secret_hex::<N>` decodes into a `Zeroizing<[u8; N]>` with
    `hex::decode_to_slice`. It refuses the same inputs as `hex::decode` plus
    a length check, with the same error and in the same order. When the length
    is wrong, it reports the first bad character, as `hex::decode` does,
    before it reports the length.
  - `parse_secret_felt` is `Felt::from_hex` into a `SecretFelt`, with the
    caller's error prefix.
- The STRK20 check now compares the digits with the felt's big-endian bytes,
  hex-encoded into a wiped stack buffer.
- `fromMnemonic` wraps the mnemonic and passphrase before it parses the
  address, and `decryptWithKey` wipes a refused plaintext.

The generated TypeScript is unchanged, since `&str` and `String` are both
`string`. With `wasm-pack build --release` for `--target web` and `nodejs`,
the JS glue is byte-identical, as are the Node `.d.ts` and every declaration
in the web `.d.ts`. The one difference is the order of members in the web
`.d.ts`'s `InitOutput` interface and in `*_bg.wasm.d.ts`. Both list the raw
WASM exports, in the linker's order, and that order moved when code moved
between codegen units. The members are the same 441 names with the same raw
signatures. The Rust signatures change, but `krusty-kms-wasm` is
`publish = false`, and nothing in the workspace depends on it. That is also
why `cargo-semver-checks` does not cover it. `wasm-exports.txt` changes on
exactly the 39 lines. `lib.rs` grows from 400 to 415 lines and `discovery.rs`
from 420 to 430, with their baselines: one wrapping line per export, the
boundary docs, and the new module declaration.

## Laws

- Accepted inputs give the same outputs, and refused inputs the same error
  messages. `tests/secret_inputs.rs` passes every secret argument with
  `.into()`, so it compiles against both signatures. It was run unchanged
  against the base branch, before the signature change, and against this
  branch. It covers case, whitespace, prefixes, wrong lengths, bad characters
  before and after a bad length, non-ASCII input, and non-UTF-8 plaintext.
- `decode_secret_hex` equals `hex::decode` plus a length check, results and
  errors alike, on 400+ inputs at three lengths: every prefix of a key and
  every one-character corruption of it.
- Existing tests keep their assertions. Their call sites change only the
  argument type (`.into()`, or `.clone()` for a reused `String`).

## Not covered

- The caller's JS string, and any copy the JS engine makes of it.
- A partial copy: `passStringToWasm0` first copies the string byte by byte, as
  ASCII. At the first non-ASCII character it re-allocates, and if the
  allocator moves the buffer, the ASCII prefix stays in the freed old buffer.
- Copies the compiler makes when it moves values (`Felt` is `Copy`), register
  spills, and stack temporaries inside `Felt::from_hex`.
- Copies inside dependencies: BIP-39 normalization and PBKDF2, scrypt,
  derivation and signing internals, `Felt` formatting, and the
  `hex::decode` inside `krusty_kms::encryption::encrypt_private_key`.
- Secrets returned to JS: derived and decrypted keys, mnemonics and
  plaintexts, discovery `*WithSecrets` JSON, and viewing keys. The Rust
  `String` that wasm-bindgen copies one out of is freed unwiped.
- The generated `private_key` accessors of `WasmKeypair`,
  `WasmStarkXOnlyKeypair`, and `WasmNostrKeypair`. The getter returns a clone,
  and the setter drops the replaced key unwiped. Fixing the setter means
  `readonly`, which changes the `.d.ts`.

## Inventory

Secret arguments of `#[wasm_bindgen]` exports on the base branch.

| Exports | Secret arguments | After |
| --- | --- | --- |
| `validateMnemonic`, `deriveKeypair`, `derivePublicKey`, `deriveStarknetKeypair`, `deriveStarknetPublicKey`, `deriveArgentLegacyKeypair`, `deriveArgentLegacyPublicKey`, `deriveNostrKeypair`, `deriveNostrPublicKey` | `mnemonic` | owned, wiped |
| `WasmAccount.fromMnemonic` | `mnemonic` | owned, wiped; passphrase wrapped before the address is parsed |
| `WasmAccount.fromPrivateKey` | `private_key` | owned, wiped; parsed into `SecretFelt` |
| `generateAccountCandidates[WithSecrets]`, `generateAccountAddresses`, `deriveDiscoveryKeypairs[WithSecrets]`, `discoverAccountsFromMnemonic[WithSecrets]` | `mnemonic` | owned, wiped |
| `encryptPrivateKey` | `private_key_hex`, `password` | owned, wiped |
| `decryptPrivateKey`, `decryptKeystore`, `decryptEthersKeystore` | `password` | owned, wiped |
| `encryptKeystore` | `mnemonic`, `password` | owned, wiped |
| `encryptWithKey` | `plaintext`, `key_hex` | owned, wiped; key decoded into `Zeroizing<[u8; 32]>` |
| `decryptWithKey` | `key_hex` | owned, wiped; key decoded into `Zeroizing<[u8; 32]>`; refused plaintext wiped |
| `wrapNostrApplicationData` | `mnemonic`, `content` | owned, wiped |
| `openNostrApplicationData` | `mnemonic` | owned, wiped |
| `starkPublicKey`, `signStarkHash` | `private_key` | owned, wiped; `SecretFelt` |
| `nostrPublicKey`, `signNostrEventId`, `signNostrMessage` | `private_key` | owned, wiped; `Zeroizing<[u8; 32]>` |
| `deriveStrk20ViewingKey`, `deriveScopedStrk20ViewingKey` | `private_key` | owned, wiped; `SecretFelt`; check no longer formats the key |
| `foldStrk20ViewingKey` | `r`, `s` (the viewing key is a function of them) | owned, wiped; as above |
| `grindKey` | `seed_hex` | owned, wiped; `Zeroizing<[u8; 32]>` |
| `isValidStarkPrivateKey` | `hex_str` | owned, wiped; `SecretFelt` |
| `scalarMul`, `scalarMulGenerator` | `scalar` (a private key for public-key derivation and ECDH) | owned, wiped; `SecretFelt` |
| `new WasmKeypair`, `new WasmStarkXOnlyKeypair`, `new WasmNostrKeypair` | `private_key` | already owned, in `ZeroizeOnDrop` structs (base branch) |
| `private_key` field setters | the replaced key | unchanged: needs `readonly` (see above) |
| `pedersenHash`, `poseidonHash[Many]`, `starknetKeccak`, `isValidFelt`, calldata and transaction-hash helpers, Tongo proof parameters | none by contract | unchanged |

Passphrases (`Option<String>`) were already owned and wiped on the base branch.

## Follow-ups

- Decode in `krusty_kms::encryption::encrypt_private_key` without
  `hex::decode`'s growing `Vec`.
- Make the keypair `private_key` fields `readonly` when the JS API can change.
